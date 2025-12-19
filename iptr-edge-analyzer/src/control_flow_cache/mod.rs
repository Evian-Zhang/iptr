//! Caches for control flow in TNT bits and TIP packets.

mod cache;
use std::mem::MaybeUninit;

pub use cache::ControlFlowCacheManager;

use iptr_decoder::DecoderContext;

use crate::{
    EdgeAnalyzer, HandleControlFlow, PreTipStatus, ReadMemory, TntProceed,
    control_flow_cache::cache::CachableInformation,
    error::{AnalyzerError, AnalyzerResult},
    tnt_buffer::TntBuffer,
};

impl<H: HandleControlFlow, R: ReadMemory> EdgeAnalyzer<'_, H, R> {
    /// Indicate that we have encountered a deferred TIP.
    ///
    /// This will re-inject the remaining TNT buffer, and set the [`pre_tip_status`][Self::pre_tip_status].
    fn mark_deferred_tip(
        &mut self,
        remain_tnt_buffer: TntBuffer,
        pre_tip_status: PreTipStatus,
    ) -> AnalyzerResult<(), H, R> {
        self.tnt_buffer_manager.prepend_buf(remain_tnt_buffer)?;
        self.pre_tip_status = pre_tip_status;

        Ok(())
    }

    /// Process a TNT buffer may or may not be full.
    ///
    /// Note that this function may re-inject tnt buffer into [`tnt_buffer_manager`][Self::tnt_buffer_manager] if
    /// a deferred TIP is detected (in that case, the remaining TNT bits should be processed
    /// AFTER the deferred TIP is processed)
    pub(crate) fn handle_maybe_full_tnt_buffer(
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
                ((remain_buffer_value >> u32::BITS) as u32).to_le_bytes(),
            )?;
            if let TntProceed::Break {
                processed_bit_count,
                pre_tip_status,
            } = tnt_proceed
            {
                let remain_buf =
                    tnt_buffer.remove_first_n_bits(processed_bit_count + total_processed_bit_count);
                self.mark_deferred_tip(remain_buf, pre_tip_status)?;
                return Ok(());
            }
            remain_bits -= u32::BITS;
            remain_buffer_value <<= u32::BITS;
            total_processed_bit_count += u32::BITS;
        }
        while remain_bits >= u8::BITS {
            let (_new_cached_key, tnt_proceed) = self.handle_tnt_buffer8(
                context,
                last_bb_ref,
                (remain_buffer_value >> (u64::BITS - u8::BITS)) as u8,
            )?;
            if let TntProceed::Break {
                processed_bit_count,
                pre_tip_status,
            } = tnt_proceed
            {
                let remain_buf =
                    tnt_buffer.remove_first_n_bits(processed_bit_count + total_processed_bit_count);
                self.mark_deferred_tip(remain_buf, pre_tip_status)?;
                return Ok(());
            }
            remain_bits -= u8::BITS;
            remain_buffer_value <<= u8::BITS;
            total_processed_bit_count += u8::BITS;
        }
        while remain_bits != 0 {
            let tnt_bit =
                (remain_buffer_value & u64::from_le_bytes([0, 0, 0, 0, 0, 0, 0, 0b1000_0000])) != 0;
            let (_new_cached_key, tnt_proceed) =
                self.process_tnt_bit_without_cache(context, last_bb_ref, tnt_bit)?;
            if let TntProceed::Break {
                processed_bit_count: _,
                pre_tip_status,
            } = tnt_proceed
            {
                // Current bit is not processed, and reserved for processing after next TIP
                let remain_buf = tnt_buffer.remove_first_n_bits(total_processed_bit_count);
                self.mark_deferred_tip(remain_buf, pre_tip_status)?;
                return Ok(());
            }
            remain_bits -= 1;
            remain_buffer_value <<= 1;
            total_processed_bit_count += 1;
        }

        Ok(())
    }

    /// A fast path for [`handle_maybe_full_tnt_buffer`][Self::handle_maybe_full_tnt_buffer] if
    /// the tnt buffer is full
    pub(crate) fn handle_full_tnt_buffer(
        &mut self,
        context: &DecoderContext,
        last_bb_ref: &mut u64,
        tnt_buffer: TntBuffer,
    ) -> AnalyzerResult<(), H, R> {
        let [b0, b1, b2, b3, b4, b5, b6, b7] = tnt_buffer.get_array_qword();
        let tnt_proceed = self.handle_tnt_buffer32(context, last_bb_ref, [b4, b5, b6, b7])?;
        if let TntProceed::Break {
            processed_bit_count,
            pre_tip_status,
        } = tnt_proceed
        {
            let remain_buf = tnt_buffer.remove_first_n_bits(processed_bit_count);
            self.mark_deferred_tip(remain_buf, pre_tip_status)?;
            return Ok(());
        }
        let tnt_proceed = self.handle_tnt_buffer32(context, last_bb_ref, [b0, b1, b2, b3])?;
        if let TntProceed::Break {
            processed_bit_count,
            pre_tip_status,
        } = tnt_proceed
        {
            let remain_buf = tnt_buffer.remove_first_n_bits(processed_bit_count + u32::BITS);
            self.mark_deferred_tip(remain_buf, pre_tip_status)?;
            return Ok(());
        }

        Ok(())
    }

    /// Handle 32 Tnt bits stored in `tnt_buffer`.
    ///
    /// The behavior and return value is much like [`handle_tnt_buffer8`][Self::handle_tnt_buffer8],
    /// only differs in that this function does not return `cached_key`, since
    /// no one will use such data any more.
    fn handle_tnt_buffer32(
        &mut self,
        context: &DecoderContext,
        last_bb_ref: &mut u64,
        tnt_buffer: [u8; 4],
    ) -> AnalyzerResult<TntProceed, H, R> {
        if let Some(cached_info) = self.cache_manager.get_dword(*last_bb_ref, tnt_buffer) {
            *last_bb_ref = cached_info.new_bb;
            if let Some(cached_key) = &cached_info.user_data {
                self.handler
                    .on_reused_cache(cached_key)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
            }

            return Ok(TntProceed::Continue);
        }
        let start_bb = *last_bb_ref;
        let mut cached_keys = [const { MaybeUninit::uninit() }; 4];
        let [b0, b1, b2, b3] = tnt_buffer;
        let (new_cached_key, tnt_proceed) = self.handle_tnt_buffer8(context, last_bb_ref, b3)?;
        if let TntProceed::Break {
            processed_bit_count,
            pre_tip_status,
        } = tnt_proceed
        {
            return Ok(TntProceed::Break {
                processed_bit_count,
                pre_tip_status,
            });
        }
        cached_keys[0].write(new_cached_key);
        let (new_cached_key, tnt_proceed) = self.handle_tnt_buffer8(context, last_bb_ref, b2)?;
        if let TntProceed::Break {
            processed_bit_count,
            pre_tip_status,
        } = tnt_proceed
        {
            return Ok(TntProceed::Break {
                processed_bit_count: processed_bit_count + u8::BITS,
                pre_tip_status,
            });
        }
        cached_keys[1].write(new_cached_key);
        let (new_cached_key, tnt_proceed) = self.handle_tnt_buffer8(context, last_bb_ref, b1)?;
        if let TntProceed::Break {
            processed_bit_count,
            pre_tip_status,
        } = tnt_proceed
        {
            return Ok(TntProceed::Break {
                processed_bit_count: processed_bit_count + u8::BITS * 2,
                pre_tip_status,
            });
        }
        cached_keys[2].write(new_cached_key);
        let (new_cached_key, tnt_proceed) = self.handle_tnt_buffer8(context, last_bb_ref, b0)?;
        if let TntProceed::Break {
            processed_bit_count,
            pre_tip_status,
        } = tnt_proceed
        {
            return Ok(TntProceed::Break {
                processed_bit_count: processed_bit_count + u8::BITS * 3,
                pre_tip_status,
            });
        }
        cached_keys[3].write(new_cached_key);

        let mut cached_key = None;
        for new_cached_key in cached_keys {
            // SAFETY: All cached keys are written
            update_cached_key(self.handler, &mut cached_key, unsafe {
                new_cached_key.assume_init()
            })?;
        }
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

    /// Handle 8 TNT bits stored in `tnt_bits`, and update `last_bb_ref`.
    ///
    /// If the deferred TIP is detected during handling, the process will
    /// stop and the function will immediately return. When there is no
    /// deferred TIP is detected, a one-byte control flow cache will be inserted
    /// by this function.
    ///
    /// If success, returns a tuple `(cached_key, tnt_proceed)`. If no deferred
    /// TIP is detected, `cached_key` will be a key used for control flow handler
    /// to reuse the result when the control flow cache is hit again; `tnt_proceed`
    /// will be [`TntProceed::Continue`]; If a deferred TIP is detected, `cached_key`
    /// will be [`None`], and `tnt_proceed` will be [`TntProceed::Break`], which
    /// contains how many bits have been processed before the deferred TIP is detected.
    ///
    /// The `cached_key` that returned by this function is used to compose dword
    /// cached key in [`handle_tnt_buffer32`][Self::handle_tnt_buffer32].
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
                    .on_reused_cache(cached_key)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
            }

            // TODO: The clone can be optimized using the `entry` API
            // and `Cow` structure.
            return Ok((cached_info.user_data.clone(), TntProceed::Continue));
        }
        let mut cached_keys = [const { MaybeUninit::uninit() }; 8];
        let start_bb = *last_bb_ref;
        // The default value does not matter. The for-loop must run at least once
        let mut tnt_proceed = TntProceed::Continue;
        for bit in (0..8).rev() {
            let tnt_bit = (tnt_bits & (1 << bit)) != 0;
            let (new_cached_key, this_tnt_proceed) =
                self.process_tnt_bit_without_cache(context, last_bb_ref, tnt_bit)?;
            tnt_proceed = this_tnt_proceed;
            if let TntProceed::Break {
                processed_bit_count: _,
                pre_tip_status,
            } = tnt_proceed
            {
                // Current bit is not processed, and reserved for processing after next TIP
                return Ok((
                    None,
                    TntProceed::Break {
                        processed_bit_count: bit,
                        pre_tip_status,
                    },
                ));
            }
            cached_keys[bit as usize].write(new_cached_key);
        }
        let mut cached_key = None;
        for new_cached_key in cached_keys {
            // SAFETY: All elements are written
            let new_cached_key = unsafe { new_cached_key.assume_init() };
            update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
        }
        // The cache will only be inserted if `TntProceed` is always `Continue`
        self.cache_manager.insert_byte(
            start_bb,
            tnt_bits,
            CachableInformation {
                user_data: cached_key.clone(),
                new_bb: *last_bb_ref,
            },
        );
        Ok((cached_key, tnt_proceed))
    }
}

/// A convenient wrapper for [`merge_cached_keys`][HandleControlFlow::merge_cached_keys]
pub(crate) fn update_cached_key<H: HandleControlFlow, R: ReadMemory>(
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
