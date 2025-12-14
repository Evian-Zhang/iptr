mod control_flow_cache;
mod control_flow_handler;
pub mod error;
mod memory_reader;
mod static_analyzer;
mod tnt_buffer;

use std::num::NonZero;

use iptr_decoder::{DecoderContext, HandlePacket, IpReconstructionPattern};

use crate::{
    control_flow_cache::{CachableInformation, ControlFlowCacheManager},
    control_flow_handler::ControlFlowTransitionKind,
    error::{AnalyzerError, AnalyzerResult},
    static_analyzer::StaticControlFlowAnalyzer,
    tnt_buffer::{TntBuffer, TntBufferManager},
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
    tnt_buffer_manager: TntBufferManager,
    cache_manager: ControlFlowCacheManager<Option<H::CachedKey>>,
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
            tnt_buffer_manager: TntBufferManager::new(),
            cache_manager: ControlFlowCacheManager::new(),
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

    fn last_bb(&self) -> u64 {
        let Some(last_bb) = self.last_bb else {
            return 0;
        };
        last_bb.get()
    }

    fn handle_tnt_buffer32(
        &mut self,
        context: &DecoderContext,
        tnt_buffer: [u8; 4],
    ) -> AnalyzerResult<(), H, R> {
        if let Some(cached_info) = self.cache_manager.get_dword(self.last_bb(), tnt_buffer) {
            self.last_bb = Some(cached_info.new_bb);
            if let Some(cached_key) = cached_info.user_data {
                self.handler
                    .on_reused_cache(cached_key)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
            }

            return Ok(());
        }
        let start_bb = self.last_bb();
        let mut cached_key = None;
        let [b0, b1, b2, b3] = tnt_buffer;
        let new_cached_key = self.handle_tnt_buffer8(context, b0)?;
        update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        let new_cached_key = self.handle_tnt_buffer8(context, b1)?;
        update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        let new_cached_key = self.handle_tnt_buffer8(context, b2)?;
        update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        let new_cached_key = self.handle_tnt_buffer8(context, b3)?;
        update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        if let Some(new_bb) = self.last_bb {
            self.cache_manager.insert_dword(
                start_bb,
                tnt_buffer,
                CachableInformation {
                    user_data: cached_key,
                    new_bb,
                },
            );
        }

        Ok(())
    }

    fn handle_tnt_buffer8(
        &mut self,
        context: &DecoderContext,
        tnt_bits: u8,
    ) -> AnalyzerResult<Option<H::CachedKey>, H, R> {
        if let Some(cached_info) = self.cache_manager.get_byte(self.last_bb(), tnt_bits) {
            self.last_bb = Some(cached_info.new_bb);
            if let Some(cached_key) = &cached_info.user_data {
                self.handler
                    .on_reused_cache(*cached_key)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
            }

            return Ok(cached_info.user_data);
        }
        let mut cached_key = None;
        let start_bb = self.last_bb();
        for bit in 0..8 {
            let tnt_bit = (tnt_bits & (1 << bit)) != 0;
            let new_cached_key = self.process_tnt_bit_without_cache(context, tnt_bit)?;
            update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        }
        if let Some(new_bb) = self.last_bb {
            self.cache_manager.insert_byte(
                start_bb,
                tnt_bits,
                CachableInformation {
                    user_data: cached_key,
                    new_bb,
                },
            );
        }
        Ok(cached_key)
    }

    fn process_tnt_bit_without_cache(
        &mut self,
        context: &DecoderContext,
        is_taken: bool,
    ) -> AnalyzerResult<Option<H::CachedKey>, H, R> {
        let Some(last_bb) = self.last_bb else {
            // No previous TIP given. Silently ignore those TNTs
            return Ok(None);
        };
        let mut cached_key = None;
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
                    let new_cached_key = self
                        .handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::ConditionalBranch)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
                    break 'cfg_traverse;
                }
                DirectGoto { target } => {
                    last_bb = target;
                    let new_cached_key = self
                        .handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::DirectJump)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
                    continue 'cfg_traverse;
                }
                DirectCall {
                    target,
                    return_address,
                } => {
                    last_bb = target;
                    let new_cached_key = self
                        .handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::DirectCall)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
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
                    let new_cached_key = self
                        .handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::Return)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
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

        Ok(cached_key)
    }
}

impl<H, R> HandlePacket for EdgeAnalyzer<'_, H, R>
where
    H: HandleControlFlow,
    R: ReadMemory,
    AnalyzerError<H, R>: std::error::Error,
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
        if let Some(full_tnt_buffer) = self.tnt_buffer_manager.extend_with_short_tnt(packet_byte) {}
        // for bit in 1..=highest_bit {
        //     let is_taken = (packet_byte & (1 << bit)) != 0;

        //     self.handle_tnt_bit(context, is_taken)?;
        // }

        Ok(())
    }

    fn on_long_tnt_packet(
        &mut self,
        context: &DecoderContext,
        packet_bytes: u64,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        if highest_bit == u32::MAX {
            // No TNT bits
            return Ok(());
        }
        if self.last_bb.is_none() {
            // No previous TIP given. Silently ignore those TNTs
            return Ok(());
        }
        if let Some(full_tnt_buffer) = self.tnt_buffer_manager.extend_with_long_tnt(packet_bytes) {}

        Ok(())
    }
}

fn update_cached_key<H: HandleControlFlow, R: ReadMemory>(
    handler: &mut H,
    cached_key: &mut Option<H::CachedKey>,
    new_cached_key: Option<H::CachedKey>,
) -> Result<(), AnalyzerError<H, R>> {
    let Some(new_cached_key) = new_cached_key else {
        return Ok(());
    };
    if let Some(old_cached_key) = cached_key.take() {
        *cached_key = Some(
            handler
                .merge_cached_keys(old_cached_key, new_cached_key)
                .map_err(AnalyzerError::ControlFlowHandler)?,
        );
    } else {
        *cached_key = Some(new_cached_key);
    }

    Ok(())
}
