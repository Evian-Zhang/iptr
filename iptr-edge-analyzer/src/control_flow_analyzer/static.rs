use hashbrown::HashMap;
use iced_x86::{Decoder as IcedDecoder, DecoderOptions as IcedDecoderOptions, Instruction};
use iptr_decoder::TraceeMode;

use crate::{
    HandleControlFlow, ReadMemory,
    error::{AnalyzerError, AnalyzerResult},
};

pub struct CfgNode {}

pub enum CfgTerminator {
    Branch { r#true: u64, r#false: u64 },
    DirectGoto { target: u64 },
    IndirectGotoOrCall,
    DirectCall { target: u64 },
    NearRet,
    FarTransfers,
}

pub struct StaticControlFlowAnalyzer {
    /// This will become very huge after running a long time
    cfg: HashMap<u64, CfgNode>,
}

impl StaticControlFlowAnalyzer {
    pub fn new() -> Self {
        Self {
            cfg: HashMap::new(),
        }
    }

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
                memory_reader
                    .read_memory(insn_addr, 16, |insn_buf| {
                        let mut decoder = IcedDecoder::new(
                            tracee_mode.bitness(),
                            insn_buf,
                            IcedDecoderOptions::NONE,
                        );
                        if !decoder.can_decode() {
                            return Err(AnalyzerError::InvalidInstruction(insn_buf.into()));
                        }
                        decoder.decode_out(&mut instruction);

                        Ok(())
                    })
                    .map_err(|err| AnalyzerError::MemoryReader(err))??;

                let node = unimplemented!();
                Ok(entry.insert(node))
            }
        }
    }
}
