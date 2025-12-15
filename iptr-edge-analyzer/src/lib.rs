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

#[derive(Clone, Copy)]
enum TntProceed {
    Continue,
    Break { processed_bit_count: u32 },
}

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
    ///
    /// # Important Notes
    ///
    /// This field is only accessed in the handler methods in [`HandlePacket`].
    /// For performance consideration, this field will never be updated during
    /// internal parsing methods such as [`handle_tnt_buffer32`][Self::handle_tnt_buffer32].
    /// As a result, you should never read this field in those methods.
    last_bb: Option<NonZero<u64>>,
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
            tnt_buffer_manager: TntBufferManager::new(),
            cache_manager: ControlFlowCacheManager::new(),
            static_analyzer: StaticControlFlowAnalyzer::new(),
            handler,
            reader,
        }
    }

    #[expect(
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::enum_glob_use
    )]
    fn reconstruct_ip_and_update_last(
        &mut self,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Option<u64> {
        use IpReconstructionPattern::*;
        let ip = match ip_reconstruction_pattern {
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

    /// Process a TNT buffer may or may not be full.
    ///
    /// Note that this function may re-inject tnt buffer into `self.tnt_buffer_manager` if
    /// a deferred TIP is detected (in that case, the remaining TNT bits should be processed
    /// AFTER the deferred TIP is processed)
    #[expect(clippy::cast_possible_truncation)]
    fn handle_maybe_full_tnt_buffer(
        &mut self,
        context: &DecoderContext,
        last_bb_ref: &mut u64,
        tnt_buffer: TntBuffer,
    ) -> AnalyzerResult<(), H, R> {
        let mut remain_bits = tnt_buffer.bits();
        if remain_bits == 0 {
            return Ok(());
        }
        let mut remain_buffer_value = u64::from_le_bytes(tnt_buffer.get_array_qword());
        let mut total_processed_bit_count = 0;
        while remain_bits >= u32::BITS {
            let tnt_proceed = self.handle_tnt_buffer32(
                context,
                last_bb_ref,
                (remain_buffer_value as u32).to_ne_bytes(),
            )?;
            if let TntProceed::Break {
                processed_bit_count,
            } = tnt_proceed
            {
                let remain_buf =
                    tnt_buffer.remove_first_n_bits(processed_bit_count + total_processed_bit_count);
                self.tnt_buffer_manager.set_buf(remain_buf);
                return Ok(());
            }
            remain_bits -= u32::BITS;
            remain_buffer_value >>= u32::BITS;
            total_processed_bit_count += u32::BITS;
        }
        while remain_bits >= u8::BITS {
            let (_new_cached_key, tnt_proceed) =
                self.handle_tnt_buffer8(context, last_bb_ref, remain_buffer_value as u8)?;
            if let TntProceed::Break {
                processed_bit_count,
            } = tnt_proceed
            {
                let remain_buf =
                    tnt_buffer.remove_first_n_bits(processed_bit_count + total_processed_bit_count);
                self.tnt_buffer_manager.set_buf(remain_buf);
                return Ok(());
            }
            remain_bits -= u8::BITS;
            remain_buffer_value >>= u8::BITS;
            total_processed_bit_count += u8::BITS;
        }
        while remain_bits != 0 {
            let tnt_bit = (remain_buffer_value & 0b1) != 0;
            let (_new_cached_key, tnt_proceed) =
                self.process_tnt_bit_without_cache(context, last_bb_ref, tnt_bit)?;
            if matches!(tnt_proceed, TntProceed::Break { .. }) {
                // Current bit is not processed, and reserved for processing after next TIP
                let remain_buf = tnt_buffer.remove_first_n_bits(total_processed_bit_count);
                self.tnt_buffer_manager.set_buf(remain_buf);
                return Ok(());
            }
            remain_bits -= 1;
            remain_buffer_value >>= 1;
            total_processed_bit_count += 1;
        }

        Ok(())
    }

    /// A fast path for [`handle_maybe_full_tnt_buffer`][Self::handle_maybe_full_tnt_buffer] if
    /// the tnt buffer is full
    fn handle_full_tnt_buffer(
        &mut self,
        context: &DecoderContext,
        last_bb_ref: &mut u64,
        tnt_buffer: TntBuffer,
    ) -> AnalyzerResult<(), H, R> {
        let [b0, b1, b2, b3, b4, b5, b6, b7] = tnt_buffer.get_array_qword();
        let tnt_proceed = self.handle_tnt_buffer32(context, last_bb_ref, [b0, b1, b2, b3])?;
        if let TntProceed::Break {
            processed_bit_count,
        } = tnt_proceed
        {
            let remain_buf = tnt_buffer.remove_first_n_bits(processed_bit_count);
            self.tnt_buffer_manager.set_buf(remain_buf);
            return Ok(());
        }
        let tnt_proceed = self.handle_tnt_buffer32(context, last_bb_ref, [b4, b5, b6, b7])?;
        if let TntProceed::Break {
            processed_bit_count,
        } = tnt_proceed
        {
            let remain_buf = tnt_buffer.remove_first_n_bits(processed_bit_count + u32::BITS);
            self.tnt_buffer_manager.set_buf(remain_buf);
            return Ok(());
        }

        Ok(())
    }

    fn handle_tnt_buffer32(
        &mut self,
        context: &DecoderContext,
        last_bb_ref: &mut u64,
        tnt_buffer: [u8; 4],
    ) -> AnalyzerResult<TntProceed, H, R> {
        if let Some(cached_info) = self.cache_manager.get_dword(*last_bb_ref, tnt_buffer) {
            *last_bb_ref = cached_info.new_bb;
            if let Some(cached_key) = cached_info.user_data {
                self.handler
                    .on_reused_cache(cached_key)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
            }

            return Ok(TntProceed::Continue);
        }
        let start_bb = *last_bb_ref;
        let mut cached_key = None;
        let [b0, b1, b2, b3] = tnt_buffer;
        let (new_cached_key, tnt_proceed) = self.handle_tnt_buffer8(context, last_bb_ref, b0)?;
        if let TntProceed::Break {
            processed_bit_count,
        } = tnt_proceed
        {
            return Ok(TntProceed::Break {
                processed_bit_count,
            });
        }
        update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        let (new_cached_key, tnt_proceed) = self.handle_tnt_buffer8(context, last_bb_ref, b1)?;
        if let TntProceed::Break {
            processed_bit_count,
        } = tnt_proceed
        {
            return Ok(TntProceed::Break {
                processed_bit_count: processed_bit_count + u8::BITS,
            });
        }
        update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        let (new_cached_key, tnt_proceed) = self.handle_tnt_buffer8(context, last_bb_ref, b2)?;
        if let TntProceed::Break {
            processed_bit_count,
        } = tnt_proceed
        {
            return Ok(TntProceed::Break {
                processed_bit_count: processed_bit_count + u8::BITS * 2,
            });
        }
        update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        let (new_cached_key, tnt_proceed) = self.handle_tnt_buffer8(context, last_bb_ref, b3)?;
        if let TntProceed::Break {
            processed_bit_count,
        } = tnt_proceed
        {
            return Ok(TntProceed::Break {
                processed_bit_count: processed_bit_count + u8::BITS * 3,
            });
        }
        update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        // The cache will only be inserted if `TntProceed` is always `Continue`
        self.cache_manager.insert_dword(
            start_bb,
            tnt_buffer,
            CachableInformation {
                user_data: cached_key,
                new_bb: *last_bb_ref,
            },
        );

        Ok(tnt_proceed)
    }

    fn handle_tnt_buffer8(
        &mut self,
        context: &DecoderContext,
        last_bb_ref: &mut u64,
        tnt_bits: u8,
    ) -> AnalyzerResult<(Option<H::CachedKey>, TntProceed), H, R> {
        if let Some(cached_info) = self.cache_manager.get_byte(*last_bb_ref, tnt_bits) {
            *last_bb_ref = cached_info.new_bb;
            if let Some(cached_key) = &cached_info.user_data {
                self.handler
                    .on_reused_cache(*cached_key)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
            }

            return Ok((cached_info.user_data, TntProceed::Continue));
        }
        let mut cached_key = None;
        let start_bb = *last_bb_ref;
        // The default value does not matter. The for-loop must run at least once
        let mut tnt_proceed = TntProceed::Continue;
        for bit in 0..8 {
            let tnt_bit = (tnt_bits & (1 << bit)) != 0;
            let (new_cached_key, this_tnt_proceed) =
                self.process_tnt_bit_without_cache(context, last_bb_ref, tnt_bit)?;
            tnt_proceed = this_tnt_proceed;
            if matches!(tnt_proceed, TntProceed::Break { .. }) {
                // Current bit is not processed, and reserved for processing after next TIP
                return Ok((
                    cached_key,
                    TntProceed::Break {
                        processed_bit_count: bit,
                    },
                ));
            }
            update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        }
        // The cache will only be inserted if `TntProceed` is always `Continue`
        self.cache_manager.insert_byte(
            start_bb,
            tnt_bits,
            CachableInformation {
                user_data: cached_key,
                new_bb: *last_bb_ref,
            },
        );
        Ok((cached_key, tnt_proceed))
    }

    #[expect(
        clippy::enum_glob_use,
        clippy::items_after_statements,
        clippy::needless_continue
    )]
    fn process_tnt_bit_without_cache(
        &mut self,
        context: &DecoderContext,
        last_bb_ref: &mut u64,
        is_taken: bool,
    ) -> AnalyzerResult<(Option<H::CachedKey>, TntProceed), H, R> {
        let mut last_bb = *last_bb_ref;
        let mut cached_key = None;
        let tnt_proceed;
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
                    tnt_proceed = TntProceed::Continue;
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
                    return_address: _,
                } => {
                    last_bb = target;
                    let new_cached_key = self
                        .handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::DirectCall)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
                    continue 'cfg_traverse;
                }
                IndirectGotoOrCall => {
                    // Wait for deferred TIP
                    tnt_proceed = TntProceed::Break {
                        processed_bit_count: 0,
                    };
                    break 'cfg_traverse;
                }
                NearRet => {
                    if !is_taken {
                        // If return is not compressed, then an immediate TIP packet will be generated.
                        // If return is compressed, then a taken bit will be generated
                        return Err(AnalyzerError::InvalidPacket);
                    }
                    return Err(AnalyzerError::UnsupportedReturnCompression);
                    // let new_cached_key = self
                    //     .handler
                    //     .on_new_block(last_bb, ControlFlowTransitionKind::Return)
                    //     .map_err(AnalyzerError::ControlFlowHandler)?;
                    // update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
                }
                FarTransfers => {
                    // Far transfers will always emit FUP packets immediately
                    return Err(AnalyzerError::InvalidPacket);
                }
            }
        }
        *last_bb_ref = last_bb;

        Ok((cached_key, tnt_proceed))
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
        let Some(last_bb) = self.last_bb else {
            // No previous TIP given. Silently ignore those TNTs
            return Ok(());
        };
        let mut last_bb = last_bb.get();
        if let Some(full_tnt_buffer) = self.tnt_buffer_manager.extend_with_short_tnt(packet_byte) {
            let res = self.handle_full_tnt_buffer(context, &mut last_bb, full_tnt_buffer);
            self.last_bb = NonZero::new(last_bb);
            res?;
        }

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
        let Some(last_bb) = self.last_bb else {
            // No previous TIP given. Silently ignore those TNTs
            return Ok(());
        };
        let mut last_bb = last_bb.get();
        if let Some(full_tnt_buffer) = self.tnt_buffer_manager.extend_with_long_tnt(packet_bytes) {
            let res = self.handle_full_tnt_buffer(context, &mut last_bb, full_tnt_buffer);
            self.last_bb = NonZero::new(last_bb);
            res?;
        }

        Ok(())
    }

    fn on_tip_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        let mut last_bb =
            if let Some(last_bb) = self.reconstruct_ip_and_update_last(ip_reconstruction_pattern) {
                self.last_bb = NonZero::new(last_bb);
                last_bb
            } else {
                let Some(last_bb) = self.last_bb else {
                    // No previous TIP given. Silently ignore those TNTs
                    return Ok(());
                };
                last_bb.get()
            };
        let tnt_buffer = self.tnt_buffer_manager.take();
        let res = self.handle_maybe_full_tnt_buffer(context, &mut last_bb, tnt_buffer);
        self.last_bb = NonZero::new(last_bb);
        res?;

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
