mod r#static;

use std::num::NonZero;

use iptr_decoder::DecoderContext;

use crate::{
    HandleControlFlow, ReadMemory,
    control_flow_analyzer::r#static::StaticControlFlowAnalyzer,
    control_flow_handler::ControlFlowTransitionKind,
    error::{AnalyzerError, AnalyzerResult},
};

pub struct ControlFlowAnalyzer {
    /// Address of previous basic block
    ///
    /// Instruction address will never be zero
    last_bb: Option<NonZero<u64>>,
    callstack: Vec<u64>,
    static_analyzer: StaticControlFlowAnalyzer,
}

impl ControlFlowAnalyzer {
    pub fn new() -> Self {
        Self {
            last_bb: None,
            callstack: vec![],
            static_analyzer: StaticControlFlowAnalyzer::new(),
        }
    }

    fn handle_tnt_bit<H: HandleControlFlow, R: ReadMemory>(
        &mut self,
        handler: &mut H,
        reader: &mut R,
        context: &DecoderContext,
        is_taken: bool,
    ) -> AnalyzerResult<(), H, R> {
        let Some(last_bb) = self.last_bb else {
            // No previous TIP given. Silently ignore those TNTs
            return Ok(());
        };
        let mut last_bb = last_bb.get();
        'cfg_traverse: loop {
            let cfg_node = self
                .static_analyzer
                .resolve(reader, context.tracee_mode(), last_bb)?;
            let terminator = cfg_node.terminator;
            use r#static::CfgTerminator::*;
            match terminator {
                Branch { r#true, r#false } => {
                    last_bb = if is_taken { r#true } else { r#false };
                    handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::ConditionalBranch)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    break 'cfg_traverse;
                }
                DirectGoto { target } => {
                    last_bb = target;
                    handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::DirectJump)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    continue 'cfg_traverse;
                }
                DirectCall {
                    target,
                    return_address,
                } => {
                    last_bb = target;
                    handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::DirectCall)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    self.callstack.push(return_address);
                    continue 'cfg_traverse;
                }
                IndirectGotoOrCall => {
                    // Wait for deferred TIP
                    break 'cfg_traverse;
                }
                NearRet => {
                    if !is_taken {
                        // If return is not compressed, then an immediate TIP packet will be generated.
                        // If return is compressed, then a taken bit will be generated
                        return Err(AnalyzerError::InvalidPacket);
                    }
                    let Some(last_bb) = self.callstack.pop() else {
                        // The call will must have been recorded according to the specification
                        return Err(AnalyzerError::CorruptedCallstack);
                    };
                    handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::Return)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                }
                FarTransfers => {
                    // Far transfers will always emit FUP packets immediately
                    return Err(AnalyzerError::InvalidPacket);
                }
            }
        }
        debug_assert_ne!(last_bb, 0, "Unexpected last BB is zero!");
        // SAFETY: No instruction address could be zero
        self.last_bb = Some(unsafe { NonZero::new_unchecked(last_bb) });

        Ok(())
    }

    pub fn on_short_tnt_packet<H: HandleControlFlow, R: ReadMemory>(
        &mut self,
        handler: &mut H,
        reader: &mut R,
        context: &DecoderContext,
        packet_byte: u8,
        highest_bit: u32,
    ) -> AnalyzerResult<(), H, R> {
        if highest_bit == 0 {
            // No TNT bits
            return Ok(());
        }
        if self.last_bb.is_none() {
            // No previous TIP given. Silently ignore those TNTs
            return Ok(());
        }
        for bit in 1..=highest_bit {
            let is_taken = (packet_byte & (1 << bit)) != 0;

            self.handle_tnt_bit(handler, reader, context, is_taken)?;
        }

        Ok(())
    }
}
