//! This module contains static control flow analyzer

use hashbrown::HashMap;
use iced_x86::{Code, Decoder as IcedDecoder, DecoderOptions as IcedDecoderOptions, Instruction};
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
#[derive(Clone, Copy)]
pub enum CfgTerminator {
    /// A conditional JMP
    Branch {
        /// Address of Taken branch
        r#true: u64,
        /// Address of Not Taken branch
        r#false: u64,
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
        /// Used for return compression, but currently this is not supported
        #[expect(unused)]
        return_address: u64,
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
    fn try_from(instruction: &Instruction) -> Option<Self> {
        let next_insn_addr = instruction.next_ip();

        if instruction.is_jcc_short_or_near() || instruction.is_loop() || instruction.is_loopcc() {
            // TODO: check whether LOOP/LOOPcc instruction can also be done this way
            let true_target = instruction.near_branch_target();
            let false_target = next_insn_addr;
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
            Some(CfgTerminator::DirectCall {
                target,
                return_address: next_insn_addr,
            })
        } else {
            match instruction.code() {
                | Code::Retnd | Code::Retnd_imm16
                | Code::Retnq | Code::Retnq_imm16
                | Code::Retnw | Code::Retnw_imm16 => Some(CfgTerminator::NearRet),
                // Far CALL
                | Code::Call_m1616 | Code::Call_m1632 | Code::Call_m1664
                | Code::Call_ptr1616 | Code::Call_ptr1632
                // Far JMP
                | Code::Jmp_m1616 | Code::Jmp_m1632 | Code::Jmp_m1664
                | Code::Jmp_ptr1616 | Code::Jmp_ptr1632
                // Far RET
                | Code::Retfd | Code::Retfd_imm16
                | Code::Retfq | Code::Retfq_imm16
                | Code::Retfw | Code::Retfw_imm16
                // Iret
                | Code::Iretd | Code::Iretq | Code::Iretw
                // Others
                | Code::Into | Code::Int1 | Code::Int3 | Code::Int_imm8
                | Code::Syscall | Code::Sysenter
                | Code::Sysexitd | Code::Sysexitq
                | Code::Sysretd | Code::Sysretq
                | Code::Vmlaunch | Code::Vmresume
                | Code::Ud0 | Code::Ud0_r16_rm16 | Code::Ud0_r32_rm32 | Code::Ud0_r64_rm64
                | Code::Ud1_r16_rm16 | Code::Ud1_r32_rm32 | Code::Ud1_r64_rm64
                | Code::Ud2 => Some(CfgTerminator::FarTransfers { next_instruction: next_insn_addr }),
                _ => None,
            }
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
const CFG_MAP_INITIAL_CAPACITY: usize = 0x10000;

impl StaticControlFlowAnalyzer {
    /// Create a new [`StaticControlFlowAnalyzer`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            cfg: HashMap::with_capacity(CFG_MAP_INITIAL_CAPACITY),
        }
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
                let mut instruction = Instruction::default();
                let mut insn_addr = insn_addr;
                let cfg_terminator = loop {
                    let (cfg_terminator, next_insn_addr) = memory_reader
                        .read_memory(insn_addr, 16, |insn_buf| {
                            let mut decoder = IcedDecoder::with_ip(
                                tracee_mode.bitness(),
                                insn_buf,
                                insn_addr,
                                IcedDecoderOptions::NONE,
                            );
                            if !decoder.can_decode() {
                                return Err(AnalyzerError::InvalidInstruction(insn_buf.into()));
                            }
                            decoder.decode_out(&mut instruction);
                            let next_insn_addr = instruction.next_ip();

                            let cfg_terminator = CfgTerminator::try_from(&instruction);

                            Ok((cfg_terminator, next_insn_addr))
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
                Ok(entry.insert(node))
            }
        }
    }
}
