mod control_flow_handler;
pub mod error;
mod memory_reader;
mod static_analyzer;
mod tnt_buffer;

use std::num::NonZero;

use iptr_decoder::{DecoderContext, HandlePacket, IpReconstructionPattern};

use crate::{
    control_flow_handler::ControlFlowTransitionKind,
    error::{AnalyzerError, AnalyzerResult},
    static_analyzer::StaticControlFlowAnalyzer,
};
pub use crate::{control_flow_handler::HandleControlFlow, memory_reader::ReadMemory};

pub struct EdgeAnalyzer<'a, H: HandleControlFlow, R: ReadMemory> {
    /// IP-reconstruction-specific field.
    ///
    /// This is not always be the last IP in the packet. It has
    /// special semantic according to Intel. Do not use thie field
    /// until you know what you are doing.
    last_ip: u64,
    /// Address of previous basic block
    ///
    /// Instruction address will never be zero
    last_bb: Option<NonZero<u64>>,
    callstack: Vec<u64>,
    static_analyzer: StaticControlFlowAnalyzer,
    handler: &'a mut H,
    reader: &'a mut R,
}

impl<'a, H: HandleControlFlow, R: ReadMemory> EdgeAnalyzer<'a, H, R> {
    pub fn new(handler: &'a mut H, reader: &'a mut R) -> Self {
        Self {
            last_ip: 0,
            last_bb: None,
            callstack: vec![],
            static_analyzer: StaticControlFlowAnalyzer::new(),
            handler,
            reader,
        }
    }

    #[expect(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    fn reconstruct_ip_and_update_last(
        &mut self,
        ip_reconstruction: IpReconstructionPattern,
    ) -> Option<u64> {
        use IpReconstructionPattern::*;
        let ip = match ip_reconstruction {
            OutOfContext => {
                // `last_ip` is not updated
                return None;
            }
            TwoBytesWithLastIp(payload) => {
                (self.last_ip & 0xFFFF_FFFF_FFFF_0000) | (payload as u64)
            }
            FourBytesWithLastIp(payload) => {
                (self.last_ip & 0xFFFF_FFFF_0000_0000) | (payload as u64)
            }
            SixBytesExtended(payload) => (((payload << 16) as i64) >> 16) as u64,
            SixBytesWithLastIp(payload) => {
                (self.last_ip & 0xFFFF_0000_0000_0000) | (payload as u64)
            }
            EightBytes(payload) => payload,
        };
        self.last_ip = ip;

        Some(ip)
    }

    fn handle_tnt_bit(
        &mut self,
        context: &DecoderContext,
        is_taken: bool,
    ) -> AnalyzerResult<(), H, R> {
        let Some(last_bb) = self.last_bb else {
            // No previous TIP given. Silently ignore those TNTs
            return Ok(());
        };
        let mut last_bb = last_bb.get();
        'cfg_traverse: loop {
            let cfg_node =
                self.static_analyzer
                    .resolve(self.reader, context.tracee_mode(), last_bb)?;
            let terminator = cfg_node.terminator;
            use static_analyzer::CfgTerminator::*;
            match terminator {
                Branch { r#true, r#false } => {
                    last_bb = if is_taken { r#true } else { r#false };
                    self.handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::ConditionalBranch)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    break 'cfg_traverse;
                }
                DirectGoto { target } => {
                    last_bb = target;
                    self.handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::DirectJump)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    continue 'cfg_traverse;
                }
                DirectCall {
                    target,
                    return_address,
                } => {
                    last_bb = target;
                    self.handler
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
                    self.handler
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
}

impl<H, R> HandlePacket for EdgeAnalyzer<'_, H, R>
where
    H: HandleControlFlow,
    AnalyzerError<H, R>: std::error::Error,
    R: ReadMemory,
{
    type Error = AnalyzerError<H, R>;

    fn on_short_tnt_packet(
        &mut self,
        context: &DecoderContext,
        packet_byte: u8,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
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

            self.handle_tnt_bit(context, is_taken)?;
        }

        Ok(())
    }
}
