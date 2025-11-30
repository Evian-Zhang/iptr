mod r#static;

use crate::{
    HandleControlFlow, ReadMemory, control_flow_analyzer::r#static::StaticControlFlowAnalyzer,
    error::AnalyzerResult,
};

pub struct ControlFlowAnalyzer {
    static_analyzer: StaticControlFlowAnalyzer,
}

impl ControlFlowAnalyzer {
    pub fn new() -> Self {
        Self {
            static_analyzer: StaticControlFlowAnalyzer::new(),
        }
    }

    pub fn on_short_tnt_packet<H: HandleControlFlow, R: ReadMemory>(
        &mut self,
        handler: &mut H,
        reader: &mut R,
        packet_byte: u8,
        highest_bit: u32,
    ) -> AnalyzerResult<(), H, R> {
        Ok(())
    }
}
