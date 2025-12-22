//! This module contains static control flow analyzer

use hashbrown::HashMap;
use iced_x86::{
    Code, Decoder as IcedDecoder, DecoderOptions as IcedDecoderOptions, FlowControl, Instruction,
};
use iptr_decoder::TraceeMode;

use crate::{
    HandleControlFlow, ReadMemory,
    error::{AnalyzerError, AnalyzerResult},
};

/// A node in CFG graph (CALL is also treated as a basic block terminator),
/// which represents a basic block.
pub struct CfgNode {
    /// The terminator of this basic block
    pub terminator: CfgTerminator,
}

/// Terminator of a CFG node.
#[derive(Clone, Copy, Debug)]
pub enum CfgTerminator {
    /// A conditional JMP
    Branch {
        /// Address of Taken branch
        r#true: u64,
        /// Low 32bits of address of Not Taken branch
        ///
        /// A branch cannot be inconsistent in high 32 bits
        r#false: u32,
    },
    /// A direct JMP
    DirectGoto {
        /// Address of jump target
        target: u64,
    },
    /// A direct CALL
    DirectCall {
        /// Address of call target
        target: u64,
    },
    /// An indirect JMP
    IndirectGoto,
    /// An indirect CALL
    IndirectCall,
    /// A RET
    NearRet,
    /// Other instructions that changes control flow
    FarTransfers {
        /// Address of instruction next to current instruction
        #[expect(unused)]
        next_instruction: u64,
    },
}

impl CfgTerminator {
    /// Convert an [`Instruction`] to a [`CfgTerminator`].
    ///
    /// Return [`None`] if this instruction does not change control flow.
    #[expect(clippy::cast_possible_truncation)]
    fn try_from(instruction: &Instruction) -> Option<Self> {
        let next_insn_addr = instruction.next_ip();

        if instruction.is_jcc_short_or_near() || instruction.is_loop() || instruction.is_loopcc() {
            // TODO: check whether LOOP/LOOPcc instruction can also be done this way
            let true_target = instruction.near_branch_target();
            let false_target = next_insn_addr as u32;
            debug_assert_eq!(
                true_target & 0xFFFF_FFFF_0000_0000,
                next_insn_addr & 0xFFFF_FFFF_0000_0000,
                "Two branch upper 32 bits mismatch!"
            );
            Some(CfgTerminator::Branch {
                r#true: true_target,
                r#false: false_target,
            })
        } else if instruction.is_jmp_near_indirect() {
            Some(CfgTerminator::IndirectGoto)
        } else if instruction.is_call_near_indirect() {
            Some(CfgTerminator::IndirectCall)
        } else if instruction.is_jmp_short_or_near() {
            let target = instruction.near_branch_target();
            Some(CfgTerminator::DirectGoto { target })
        } else if instruction.is_call_near() {
            let target = instruction.near_branch_target();
            Some(CfgTerminator::DirectCall { target })
        } else if matches!(
            instruction.code(),
            Code::Retnd
                | Code::Retnd_imm16
                | Code::Retnq
                | Code::Retnq_imm16
                | Code::Retnw
                | Code::Retnw_imm16
        ) {
            Some(CfgTerminator::NearRet)
        } else if !matches!(instruction.flow_control(), FlowControl::Next) {
            Some(CfgTerminator::FarTransfers {
                next_instruction: next_insn_addr,
            })
        } else {
            None
        }
    }
}

/// Static control flow analyzer, maintaining a CFG graph
pub struct StaticControlFlowAnalyzer {
    /// A CFG graph. Key: address of basic block, Value: basic block information
    ///
    /// This will become very huge after running a long time
    cfg: HashMap<u64, CfgNode>,
}

/// Initial capacity for CFG map.
///
/// The CFG map could grow dramatically, so we can initialize with a relative-large
/// capacity.
const CFG_MAP_INITIAL_CAPACITY: usize = 0x1000;

impl StaticControlFlowAnalyzer {
    /// Create a new [`StaticControlFlowAnalyzer`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            cfg: HashMap::with_capacity(CFG_MAP_INITIAL_CAPACITY),
        }
    }

    /// Get the size of CFG nodes
    pub fn cfg_size(&self) -> usize {
        self.cfg.len()
    }

    /// Resolve the given `insn_addr` to a [`CfgNode`].
    ///
    /// The `insn_addr` should be the start address of a basic block, and
    /// will always be inserted to the CFG graph.
    ///
    /// This function will read memory at `insn_addr` by querying the
    /// `memory_reader`, and decoding the corresponding instruction until
    /// reach a basic block terminator.
    pub fn resolve<H: HandleControlFlow, R: ReadMemory>(
        &mut self,
        memory_reader: &mut R,
        tracee_mode: TraceeMode,
        insn_addr: u64,
    ) -> AnalyzerResult<&mut CfgNode, H, R> {
        match self.cfg.entry(insn_addr) {
            hashbrown::hash_map::Entry::Occupied(entry) => Ok(entry.into_mut()),
            hashbrown::hash_map::Entry::Vacant(entry) => {
                Ok(entry.insert(calculate_terminator(memory_reader, tracee_mode, insn_addr)?))
            }
        }
    }
}

#[expect(clippy::too_many_lines)]
fn calculate_terminator<H: HandleControlFlow, R: ReadMemory>(
    memory_reader: &mut R,
    tracee_mode: TraceeMode,
    insn_addr: u64,
) -> AnalyzerResult<CfgNode, H, R> {
    let mut instruction = Instruction::default();
    let mut insn_addr = insn_addr;
    let mut cross_page_insn_buf = [0u8; 16];
    let mut cross_page_insn_processed_bytes = None;
    let cfg_terminator = loop {
        let (cfg_terminator, next_insn_addr) = memory_reader
            .read_memory(insn_addr, 4096, |mut insn_buf| {
                let mut insn_addr = insn_addr;
                if let Some(processed_bytes) = cross_page_insn_processed_bytes.take() {
                    // Previously we have a cross-page instruction
                    let remain_bytes = 16 - processed_bytes;
                    // remain bytes will never be zero since processed bytes is always less than 16
                    let Some(remain_buf) = insn_buf.get(0..remain_bytes) else {
                        // Very unexpected. This means the next page is also missing?
                        return Err(AnalyzerError::InvalidInstruction);
                    };
                    // SAFETY: remain buf has remain_bytes length, and processed_bytes + remain_bytes == 16
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            remain_buf.as_ptr(),
                            cross_page_insn_buf.as_mut_ptr().add(processed_bytes),
                            remain_bytes,
                        );
                    }
                    let mut decoder = IcedDecoder::with_ip(
                        tracee_mode.bitness(),
                        &cross_page_insn_buf,
                        insn_addr - processed_bytes as u64,
                        IcedDecoderOptions::NONE,
                    );
                    if !decoder.can_decode() {
                        // Unexpected! The instruction length exceeds 16 bytes?
                        return Err(AnalyzerError::Unexpected);
                    }
                    decoder.decode_out(&mut instruction);
                    if instruction.is_invalid() {
                        // Even concated cross page instruction, it is still invalid
                        return Err(AnalyzerError::InvalidInstruction);
                    }
                    let next_insn_addr = instruction.next_ip();
                    if let Some(cfg_terminator) = CfgTerminator::try_from(&instruction) {
                        cross_page_insn_buf = [0u8; 16];
                        return Ok((Some(cfg_terminator), next_insn_addr));
                    }

                    let instr_len = instruction.len();
                    // If instr len is less than remain bytes, why the previous round does not decode it out?
                    debug_assert!(instr_len >= processed_bytes, "Unexpected");
                    let Some(next_insn_buf) = insn_buf.get((instr_len - processed_bytes)..) else {
                        return Err(AnalyzerError::Unexpected);
                    };
                    insn_buf = next_insn_buf;
                    insn_addr += (instr_len - processed_bytes) as u64;
                    cross_page_insn_buf = [0u8; 16];
                }

                let mut decoder = IcedDecoder::with_ip(
                    tracee_mode.bitness(),
                    insn_buf,
                    insn_addr,
                    IcedDecoderOptions::NONE,
                );
                let mut last_next_insn_addr = None;
                loop {
                    if !decoder.can_decode() {
                        let Some(next_insn_addr) = last_next_insn_addr else {
                            // Even the first instruction cannot be decoded
                            return Err(AnalyzerError::InvalidInstruction);
                        };
                        // Have readed all instructions
                        return Ok((None, next_insn_addr));
                    }
                    let instr_pos = decoder.position();
                    decoder.decode_out(&mut instruction);
                    if instruction.is_invalid() {
                        let processed_bytes = insn_buf.len().saturating_sub(instr_pos);
                        if processed_bytes >= 16 {
                            return Err(AnalyzerError::InvalidInstruction);
                        }
                        // This instruction may cross page
                        let next_insn_addr = instruction.ip() + processed_bytes as u64;
                        // SAFETY: Bounds: saturating sub is always less than or equal to
                        debug_assert!(
                            instr_pos + processed_bytes <= insn_buf.len(),
                            "Unexpected oob read"
                        );
                        // SAFETY: Bounds: checked in if-guard
                        debug_assert!(
                            processed_bytes <= cross_page_insn_buf.len(),
                            "Unexpected oob write"
                        );
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                insn_buf.as_ptr().add(instr_pos),
                                cross_page_insn_buf.as_mut_ptr(),
                                processed_bytes,
                            );
                        }
                        cross_page_insn_processed_bytes = Some(processed_bytes);
                        return Ok((None, next_insn_addr));
                    }

                    let next_insn_addr = instruction.next_ip();
                    last_next_insn_addr = Some(next_insn_addr);

                    if let Some(cfg_terminator) = CfgTerminator::try_from(&instruction) {
                        return Ok((Some(cfg_terminator), next_insn_addr));
                    }
                }
            })
            .map_err(AnalyzerError::MemoryReader)??;

        if let Some(cfg_terminator) = cfg_terminator {
            break cfg_terminator;
        }
        insn_addr = next_insn_addr;
    };
    let node = CfgNode {
        terminator: cfg_terminator,
    };
    Ok(node)
}
