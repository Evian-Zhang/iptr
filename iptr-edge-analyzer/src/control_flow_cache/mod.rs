//! Caches for control flow in TNT bits and TIP packets.

#[cfg(feature = "cache")]
mod cache;
use std::mem::MaybeUninit;

#[cfg(feature = "cache")]
pub use cache::ControlFlowCacheManager;

use iptr_decoder::DecoderContext;

#[cfg(feature = "cache")]
use self::cache::{CachableInformation, TrailingBits};
#[cfg(feature = "cache")]
use crate::error::AnalyzerError;
use crate::{
    EdgeAnalyzer, HandleControlFlow, PreTipStatus, ReadMemory, TntProceed, error::AnalyzerResult,
    tnt_buffer::TntBuffer,
};

#[cfg(feature = "cache")]
type CachedKey<H> = <H as HandleControlFlow>::CachedKey;
#[cfg(not(feature = "cache"))]
type CachedKey<H> = std::marker::PhantomData<H>;

impl<H: HandleControlFlow, R: ReadMemory> EdgeAnalyzer<H, R> {
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
        let remain_bits = tnt_buffer.bits();
        let round8 = remain_bits / 8;
        let round1 = remain_bits % 8;
        let mut remain_buffer_value = u32::from_le_bytes(tnt_buffer.get_array_dword());
        for round in 0..round8 {
            let (_new_cached_key, tnt_proceed) = self.handle_tnt_buffer8(
                context,
                last_bb_ref,
                (remain_buffer_value >> (u32::BITS - u8::BITS)) as u8,
            )?;
            if let TntProceed::Break {
                processed_bit_count,
                pre_tip_status,
            } = tnt_proceed
            {
                let remain_buf =
                    tnt_buffer.remove_first_n_bits(processed_bit_count + round * u8::BITS);
                self.mark_deferred_tip(remain_buf, pre_tip_status)?;
                return Ok(());
            }
            remain_buffer_value <<= u8::BITS;
        }
        if round1 != 0 {
            let tnt_proceed = self.handle_tnt_buffer_trailing_bits(
                context,
                last_bb_ref,
                remain_buffer_value,
                round1,
            )?;
            if let TntProceed::Break {
                processed_bit_count,
                pre_tip_status,
            } = tnt_proceed
            {
                let remain_buf =
                    tnt_buffer.remove_first_n_bits(processed_bit_count + round8 * u8::BITS);
                self.mark_deferred_tip(remain_buf, pre_tip_status)?;
                return Ok(());
            }
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
        let [b0, b1, b2, b3] = tnt_buffer.get_array_dword();
        let tnt_proceed = self.handle_tnt_buffer32(context, last_bb_ref, [b0, b1, b2, b3])?;
        if let TntProceed::Break {
            processed_bit_count,
            pre_tip_status,
        } = tnt_proceed
        {
            let remain_buf = tnt_buffer.remove_first_n_bits(processed_bit_count);
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
        #[cfg(feature = "cache")]
        if let Some(cached_info) = self.cache_manager.get_dword(*last_bb_ref, tnt_buffer) {
            #[cfg(feature = "more_diagnose")]
            {
                self.cache_32bit_hit_count += 1;
            }
            *last_bb_ref = cached_info.new_bb;
            if let Some(cached_key) = &cached_info.user_data {
                self.handler
                    .on_reused_cache(cached_key, cached_info.new_bb)
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

        #[cfg(feature = "cache")]
        {
            // Here we make sure handler's cache has already been cleared
            self.handler
                .clear_current_cache()
                .map_err(AnalyzerError::ControlFlowHandler)?;
            for new_cached_key in cached_keys {
                // SAFETY: All cached keys are written
                update_cached_key(&mut self.handler, unsafe { new_cached_key.assume_init() })?;
            }
            // The cache will only be inserted if `TntProceed` is always `Continue`
            let cached_key = self
                .handler
                .take_cache()
                .map_err(AnalyzerError::ControlFlowHandler)?;
            self.cache_manager.insert_dword(
                start_bb,
                tnt_buffer,
                CachableInformation {
                    user_data: cached_key,
                    new_bb: *last_bb_ref,
                },
            );
        }
        #[cfg(not(feature = "cache"))]
        {
            let _ = start_bb;
            let _ = cached_keys;
        }

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
    ) -> AnalyzerResult<(Option<CachedKey<H>>, TntProceed), H, R> {
        #[cfg(feature = "cache")]
        if let Some(cached_info) = self.cache_manager.get_byte(*last_bb_ref, tnt_bits) {
            #[cfg(feature = "more_diagnose")]
            {
                self.cache_8bit_hit_count += 1;
            }
            *last_bb_ref = cached_info.new_bb;
            if let Some(cached_key) = &cached_info.user_data {
                self.handler
                    .on_reused_cache(cached_key, cached_info.new_bb)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
            }

            // TODO: The clone can be optimized using the `entry` API
            // and `Cow` structure.
            return Ok((cached_info.user_data.clone(), TntProceed::Continue));
        }
        #[cfg(feature = "cache")]
        self.handler
            .clear_current_cache()
            .map_err(AnalyzerError::ControlFlowHandler)?;
        let start_bb = *last_bb_ref;
        // The default value does not matter. The for-loop must run at least once
        for bit in (0..8).rev() {
            let tnt_bit = (tnt_bits & (1 << bit)) != 0;
            let tnt_proceed =
                self.process_tnt_bit_without_querying_cache(context, last_bb_ref, tnt_bit)?;
            if let TntProceed::Break {
                processed_bit_count: _,
                pre_tip_status,
            } = tnt_proceed
            {
                // Current bit is not processed, and reserved for processing after next TIP
                return Ok((
                    None,
                    TntProceed::Break {
                        processed_bit_count: 7 - bit,
                        pre_tip_status,
                    },
                ));
            }
        }
        #[cfg(feature = "cache")]
        {
            let cached_key = self
                .handler
                .take_cache()
                .map_err(AnalyzerError::ControlFlowHandler)?;
            // The cache will only be inserted if `TntProceed` is always `Continue`
            self.cache_manager.insert_byte(
                start_bb,
                tnt_bits,
                CachableInformation {
                    user_data: cached_key.clone(),
                    new_bb: *last_bb_ref,
                },
            );
            Ok((cached_key, TntProceed::Continue))
        }
        #[cfg(not(feature = "cache"))]
        {
            let _ = start_bb;
            Ok((None, TntProceed::Continue))
        }
    }

    /// `remain_bits` shall be in range 1..=7
    fn handle_tnt_buffer_trailing_bits(
        &mut self,
        context: &DecoderContext,
        last_bb_ref: &mut u64,
        mut remain_tnt_buffer: u32,
        remain_bits: u32,
    ) -> AnalyzerResult<TntProceed, H, R> {
        debug_assert!((1..=7).contains(&remain_bits), "Unexpected remain bits");
        #[cfg(feature = "cache")]
        let trailing_bits = TrailingBits::new(remain_tnt_buffer, remain_bits);
        #[cfg(feature = "cache")]
        if let Some(cached_info) = self
            .cache_manager
            .get_trailing_bits(*last_bb_ref, trailing_bits)
        {
            #[cfg(feature = "more_diagnose")]
            {
                self.cache_trailing_bits_hit_count += 1;
            }
            *last_bb_ref = cached_info.new_bb;
            if let Some(cached_key) = &cached_info.user_data {
                self.handler
                    .on_reused_cache(cached_key, cached_info.new_bb)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
            }

            return Ok(TntProceed::Continue);
        }
        #[cfg(feature = "cache")]
        self.handler
            .clear_current_cache()
            .map_err(AnalyzerError::ControlFlowHandler)?;
        let start_bb = *last_bb_ref;
        for bit in (0..remain_bits).rev() {
            let tnt_bit = (remain_tnt_buffer & (1 << 31)) != 0;
            let tnt_proceed =
                self.process_tnt_bit_without_querying_cache(context, last_bb_ref, tnt_bit)?;
            if let TntProceed::Break {
                processed_bit_count: _,
                pre_tip_status,
            } = tnt_proceed
            {
                // Current bit is not processed, and reserved for processing after next TIP
                return Ok(TntProceed::Break {
                    processed_bit_count: remain_bits - bit - 1,
                    pre_tip_status,
                });
            }
            remain_tnt_buffer <<= 1;
        }
        #[cfg(feature = "cache")]
        {
            // The cache will only be inserted if `TntProceed` is always `Continue`
            let cached_key = self
                .handler
                .take_cache()
                .map_err(AnalyzerError::ControlFlowHandler)?;
            self.cache_manager.insert_trailing_bits(
                start_bb,
                trailing_bits,
                CachableInformation {
                    user_data: cached_key,
                    new_bb: *last_bb_ref,
                },
            );
            Ok(TntProceed::Continue)
        }
        #[cfg(not(feature = "cache"))]
        {
            let _ = start_bb;
            Ok(TntProceed::Continue)
        }
    }
}

/// A convenient wrapper for [`merge_cached_keys`][HandleControlFlow::merge_cached_keys]
#[cfg(feature = "cache")]
fn update_cached_key<H: HandleControlFlow, R: ReadMemory>(
    handler: &mut H,
    new_cached_key: Option<H::CachedKey>,
) -> Result<(), AnalyzerError<H, R>> {
    let Some(new_cached_key) = new_cached_key else {
        return Ok(());
    };
    handler
        .cache_prev_cached_key(new_cached_key)
        .map_err(AnalyzerError::ControlFlowHandler)?;
    Ok(())
}
