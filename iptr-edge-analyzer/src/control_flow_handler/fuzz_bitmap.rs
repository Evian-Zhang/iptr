//! This module contains fuzz bitmap control flow handler logics.

#[cfg(feature = "cache")]
use std::{num::NonZero, ops::Range};

use crate::{ControlFlowTransitionKind, HandleControlFlow};

/// [`HandleControlFlow`] implementor for maintaining fuzzing bitmap
pub struct FuzzBitmapControlFlowHandler<M: AsRef<[u8]> + AsMut<[u8]>> {
    /// Already recorded bitmap indices in current cache.
    ///
    /// This is used for quickly locate bitmap count in [`per_cache_bitmap`][Self::per_cache_bitmap].
    #[cfg(feature = "cache")]
    per_cache_recorded_bitmap_indices: Vec<u32>,
    /// Bitmap like fuzzing bitmap, but used for current cache only.
    ///
    /// This is created with the same size as fuzzing bitmap, while each element indicates
    /// the count of transition among this cache in the corresponding position.
    #[cfg(feature = "cache")]
    per_cache_bitmap: Box<[u8]>,
    /// This is the actual structure holding the cache data. The cached key
    /// is a range into this list, and each element is a (pos, count) pair.
    ///
    /// This list will always have one dummy element at decode begin. By this approach,
    /// we can make sure the real indices into this list are always non-zero, which can
    /// make the cached key even smaller using Rust's niche optimization.
    #[cfg(feature = "cache")]
    bitmap_entries_arena: Vec<CompactBitmapEntry>,
    /// The fuzzing bitmap needed to be maintained.
    fuzzing_bitmap: M,
    /// Previous location used to calculating fuzzing bitmap index.
    prev_loc: u64,
}

/// Initial size of [`per_cache_recorded_bitmap_indices`][FuzzBitmapControlFlowHandler::per_cache_recorded_bitmap_indices].
#[cfg(feature = "cache")]
const INITIAL_RESULTS_PER_CACHE: usize = 64;
/// Initial size of [`bitmap_entries_arena`][FuzzBitmapControlFlowHandler::bitmap_entries_arena].
#[cfg(feature = "cache")]
const INITIAL_BITMAP_ENTRIES_ARENA_SIZE: usize = 0x100;

impl<M: AsRef<[u8]> + AsMut<[u8]>> FuzzBitmapControlFlowHandler<M> {
    /// Create a new fuzz bitmap control flow handler.
    ///
    /// You can pass things like `&mut [u8]`, `Vec<u8>`, `Box<[u8]>`, or even a mmaped structure.
    pub fn new(fuzzing_bitmap: M) -> Self {
        #[cfg(feature = "cache")]
        let bitmap_size = fuzzing_bitmap.as_ref().len();
        #[cfg(feature = "cache")]
        let mut bitmap_entries_arena = Vec::with_capacity(INITIAL_BITMAP_ENTRIES_ARENA_SIZE);
        #[cfg(feature = "cache")]
        bitmap_entries_arena.push(DUMMY_BITMAP_ENTRY);
        Self {
            #[cfg(feature = "cache")]
            per_cache_recorded_bitmap_indices: Vec::with_capacity(INITIAL_RESULTS_PER_CACHE),
            #[cfg(feature = "cache")]
            per_cache_bitmap: vec![0u8; bitmap_size].into_boxed_slice(),
            #[cfg(feature = "cache")]
            bitmap_entries_arena,
            fuzzing_bitmap,
            prev_loc: 0,
        }
    }

    /// Get fuzz bitmap size as a modulus for calculating bitmap index
    fn bitmap_size_modulus(&self) -> u64 {
        self.fuzzing_bitmap.as_ref().len() as u64
    }

    /// Update [`prev_loc`][FuzzBitmapControlFlowHandler::prev_loc] and calculate bitmap index
    #[expect(clippy::cast_possible_truncation)]
    fn on_new_loc(&mut self, new_loc: u64) -> usize {
        let bitmap_index = self.prev_loc ^ new_loc;
        self.set_new_loc(new_loc);
        (bitmap_index % self.bitmap_size_modulus()) as usize
    }

    /// Set [`prev_loc`][FuzzBitmapControlFlowHandler::prev_loc] without calculating bitmap index
    fn set_new_loc(&mut self, new_loc: u64) {
        self.prev_loc = new_loc >> 1;
    }

    /// Get diagnose information
    pub fn diagnose(&self) -> FuzzBitmapDiagnosticInformation {
        FuzzBitmapDiagnosticInformation {
            #[cfg(feature = "cache")]
            bitmap_entries_count: self.bitmap_entries_arena.len(),
        }
    }
}

/// Diagnostic information for [`FuzzBitmapControlFlowHandler`].
///
/// This struct can be retrieved from [`FuzzBitmapControlFlowHandler::diagnose`]
pub struct FuzzBitmapDiagnosticInformation {
    /// Number of raw bitmap entries stored in cache structure
    #[cfg(feature = "cache")]
    pub bitmap_entries_count: usize,
}

impl<M: AsRef<[u8]> + AsMut<[u8]>> HandleControlFlow for FuzzBitmapControlFlowHandler<M> {
    type Error = std::convert::Infallible;
    #[cfg(feature = "cache")]
    type CachedKey = PerCacheBitmapEntries;

    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        self.prev_loc = 0;
        #[cfg(feature = "cache")]
        self.clear_current_cache();
        Ok(())
    }

    #[inline]
    #[cfg_attr(feature = "cache", expect(clippy::cast_possible_truncation))]
    #[expect(clippy::enum_glob_use)]
    fn on_new_block(
        &mut self,
        block_addr: u64,
        transition_kind: ControlFlowTransitionKind,
        cache: bool,
    ) -> Result<(), Self::Error> {
        use ControlFlowTransitionKind::*;
        match transition_kind {
            ConditionalBranch | IndirectJump | IndirectCall | FarTransfer => {
                let bitmap_index = self.on_new_loc(block_addr);
                debug_assert!(
                    bitmap_index < self.fuzzing_bitmap.as_ref().len(),
                    "Unexpected OOB"
                );
                let count = unsafe { self.fuzzing_bitmap.as_mut().get_unchecked_mut(bitmap_index) };
                *count = count.wrapping_add(1);
                #[cfg(feature = "cache")]
                if cache {
                    // SAFETY: bitmap index is caculated by modulo
                    debug_assert!(bitmap_index < self.per_cache_bitmap.len(), "Unexpected OOB");
                    let count = unsafe { self.per_cache_bitmap.get_unchecked_mut(bitmap_index) };
                    if *count == 0 {
                        debug_assert!(u32::try_from(bitmap_index).is_ok(), "Bitmap size too large");
                        self.per_cache_recorded_bitmap_indices
                            .push(bitmap_index as u32);
                    }
                    *count = count.wrapping_add(1);
                }
                #[cfg(not(feature = "cache"))]
                let _ = cache;
            }
            NewBlock => {
                self.set_new_loc(block_addr);
            }
            Return | DirectJump | DirectCall => {}
        }
        Ok(())
    }

    #[cfg(feature = "cache")]
    #[expect(clippy::cast_possible_truncation)]
    fn cache_prev_cached_key(&mut self, cached_key: Self::CachedKey) -> Result<(), Self::Error> {
        let entries_range = cached_key.to_range();
        // SAFETY: bitmap entries arena will never shrink
        debug_assert!(
            entries_range.end <= self.bitmap_entries_arena.len(),
            "Unexpected OOB"
        );
        let bitmap_entries = unsafe { self.bitmap_entries_arena.get_unchecked(entries_range) };
        for bitmap_entry in bitmap_entries {
            let bitmap_index = bitmap_entry.bitmap_index();
            // SAFETY: bitmap index is caculated by modulo
            debug_assert!(bitmap_index < self.per_cache_bitmap.len(), "Unexpected OOB");
            let count = unsafe { self.per_cache_bitmap.get_unchecked_mut(bitmap_index) };
            if *count == 0 {
                debug_assert!(u32::try_from(bitmap_index).is_ok(), "Bitmap size too large");
                self.per_cache_recorded_bitmap_indices
                    .push(bitmap_index as u32);
            }
            *count = count.wrapping_add(bitmap_entry.bitmap_count());
        }

        Ok(())
    }

    #[cfg(feature = "cache")]
    fn clear_current_cache(&mut self) -> Result<(), Self::Error> {
        for bitmap_index in self.per_cache_recorded_bitmap_indices.drain(..) {
            let bitmap_index = bitmap_index as usize;
            // SAFETY: bitmap index is caculated by modulo
            debug_assert!(bitmap_index < self.per_cache_bitmap.len(), "Unexpected OOB");
            let count = unsafe { self.per_cache_bitmap.get_unchecked_mut(bitmap_index) };
            *count = 0;
        }
        Ok(())
    }

    #[cfg(feature = "cache")]
    #[expect(clippy::cast_possible_truncation)]
    fn take_cache(&mut self) -> Result<Option<Self::CachedKey>, Self::Error> {
        let start_index = self.bitmap_entries_arena.len();
        for bitmap_index in self.per_cache_recorded_bitmap_indices.drain(..) {
            let bitmap_index = bitmap_index as usize;
            // SAFETY: bitmap index is caculated by modulo
            debug_assert!(bitmap_index < self.per_cache_bitmap.len(), "Unexpected OOB");
            let count = unsafe { self.per_cache_bitmap.get_unchecked_mut(bitmap_index) };

            let bitmap_entry = CompactBitmapEntry::new(bitmap_index, *count);
            self.bitmap_entries_arena.push(bitmap_entry);

            *count = 0;
        }
        let end_index = self.bitmap_entries_arena.len();
        if start_index == end_index {
            // No new bitmap entries
            return Ok(None);
        }
        // SAFETY: bitmap entries arena always have a dummy first element, so index will never be zero
        debug_assert!(start_index > 0 && end_index > 0, "Unexpected!");
        debug_assert!(
            u32::try_from(start_index).is_ok() && u32::try_from(end_index).is_ok(),
            "Too many bitmap entries!"
        );
        let start_index = unsafe { NonZero::new_unchecked(start_index as u32) };
        let end_index = unsafe { NonZero::new_unchecked(end_index as u32) };

        Ok(Some(PerCacheBitmapEntries {
            start: start_index,
            end: end_index,
        }))
    }

    #[cfg(feature = "cache")]
    fn on_reused_cache(
        &mut self,
        cached_key: &Self::CachedKey,
        new_bb: u64,
    ) -> Result<(), Self::Error> {
        let entries_range = cached_key.to_range();
        // SAFETY: bitmap entries arena will never shrink
        debug_assert!(
            entries_range.end <= self.bitmap_entries_arena.len(),
            "Unexpected OOB"
        );
        let bitmap_entries = unsafe { self.bitmap_entries_arena.get_unchecked(entries_range) };
        for bitmap_entry in bitmap_entries {
            let bitmap_index = bitmap_entry.bitmap_index();
            debug_assert!(
                bitmap_index < self.fuzzing_bitmap.as_ref().len(),
                "Unexpected OOB"
            );
            let count = unsafe { self.fuzzing_bitmap.as_mut().get_unchecked_mut(bitmap_index) };
            *count = count.wrapping_add(bitmap_entry.bitmap_count());
        }
        self.set_new_loc(new_bb);

        Ok(())
    }
}

/// Dummy bitmap entry used to make sure the index of [`bitmap_entries_arena`][FuzzBitmapControlFlowHandler::bitmap_entries_arena]
/// will never be zero
#[cfg(feature = "cache")]
const DUMMY_BITMAP_ENTRY: CompactBitmapEntry = CompactBitmapEntry { value: 0 };

/// Compact representation of a (pos, count) pair used for fuzzing bitmap
#[cfg(feature = "cache")]
#[derive(Clone, Copy)]
struct CompactBitmapEntry {
    /// The actual value.
    ///
    /// The lower 24 bits is the pos, and the upper 8 bits is the count
    value: u32,
}

#[cfg(feature = "cache")]
impl CompactBitmapEntry {
    /// Create a new compact bitmap entry. The bitmap index should never greater
    /// than `0x00FF_FFFF`.
    #[expect(clippy::cast_possible_truncation)]
    fn new(bitmap_index: usize, bitmap_count: u8) -> Self {
        debug_assert!(bitmap_index <= 0x00FF_FFFF, "Bitmap size too large");
        let bitmap_index = bitmap_index as u32 & 0x00FF_FFFF;
        Self {
            value: bitmap_index | ((bitmap_count as u32) << 24),
        }
    }

    /// Get the bitmap index
    fn bitmap_index(self) -> usize {
        (self.value & 0x00FF_FFFF) as usize
    }

    /// Get the bitmap count
    fn bitmap_count(self) -> u8 {
        (self.value >> 24) as u8
    }
}

/// Cached key for [`FuzzBitmapControlFlowHandler`]
///
/// The cached key is a range into the [`bitmap_entries_arena`][FuzzBitmapControlFlowHandler::bitmap_entries_arena].
#[cfg(feature = "cache")]
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct PerCacheBitmapEntries {
    /// Start of range, inclusive
    start: NonZero<u32>,
    /// End of range, exclusive
    end: NonZero<u32>,
}

#[cfg(feature = "cache")]
impl PerCacheBitmapEntries {
    /// Get the range of bitmap entries
    fn to_range(self) -> Range<usize> {
        (self.start.get() as usize)..(self.end.get() as usize)
    }
}
