use std::{num::NonZero, ops::Range};

use crate::{ControlFlowTransitionKind, HandleControlFlow};

pub struct FuzzBitmapControlFlowHandler<M: AsRef<[u8]> + AsMut<[u8]>> {
    per_cache_recorded_bitmap_indices: Vec<u32>,
    per_cache_bitmap: Box<[u8]>,
    bitmap_entries_arena: Vec<CompactBitmapEntry>,
    fuzz_bitmap: M,
    prev_loc: u64,
}

const INITIAL_RESULTS_PER_CACHE: usize = 64;
const INITIAL_BITMAP_ENTRIES_ARENA_SIZE: usize = 0x100;

impl<M: AsRef<[u8]> + AsMut<[u8]>> FuzzBitmapControlFlowHandler<M> {
    pub fn new(fuzz_bitmap: M) -> Self {
        let bitmap_size = fuzz_bitmap.as_ref().len();
        let mut bitmap_entries_arena = Vec::with_capacity(INITIAL_BITMAP_ENTRIES_ARENA_SIZE);
        bitmap_entries_arena.push(DUMMY_BITMAP_ENTRY);
        Self {
            per_cache_recorded_bitmap_indices: Vec::with_capacity(INITIAL_RESULTS_PER_CACHE),
            per_cache_bitmap: vec![0u8; bitmap_size].into_boxed_slice(),
            bitmap_entries_arena,
            fuzz_bitmap,
            prev_loc: 0,
        }
    }

    fn bitmap_size_modulo(&self) -> u64 {
        self.per_cache_bitmap.len() as u64
    }

    fn on_new_loc(&mut self, new_loc: u64) -> usize {
        let bitmap_index = self.prev_loc ^ new_loc;
        self.set_new_loc(new_loc);
        (bitmap_index % self.bitmap_size_modulo()) as usize
    }

    /// Set `prev_loc` without calculating bitmap index
    fn set_new_loc(&mut self, new_loc: u64) {
        self.prev_loc = new_loc >> 1;
    }
}

impl<M: AsRef<[u8]> + AsMut<[u8]>> HandleControlFlow for FuzzBitmapControlFlowHandler<M> {
    type Error = std::convert::Infallible;
    type CachedKey = PerCacheBitmapEntries;

    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        self.prev_loc = 0;
        for bitmap_index in self.per_cache_recorded_bitmap_indices.drain(..) {
            let bitmap_index = bitmap_index as usize;
            // SAFETY: bitmap index is caculated by modulo
            debug_assert!(bitmap_index < self.per_cache_bitmap.len(), "Unexpected OOB");
            let count = unsafe { self.per_cache_bitmap.get_unchecked_mut(bitmap_index) };
            *count = 0;
        }
        Ok(())
    }

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
                    bitmap_index < self.fuzz_bitmap.as_ref().len(),
                    "Unexpected OOB"
                );
                let count = unsafe { self.fuzz_bitmap.as_mut().get_unchecked_mut(bitmap_index) };
                *count = count.wrapping_add(1);
                if cache {
                    // SAFETY: bitmap index is caculated by modulo
                    debug_assert!(bitmap_index < self.per_cache_bitmap.len(), "Unexpected OOB");
                    let count = unsafe { self.per_cache_bitmap.get_unchecked_mut(bitmap_index) };
                    if *count == 0 {
                        debug_assert!(bitmap_index <= u32::MAX as usize, "Bitmap size too large");
                        self.per_cache_recorded_bitmap_indices
                            .push(bitmap_index as u32);
                    }
                    *count = count.wrapping_add(1);
                }
            }
            NewBlock => {
                self.set_new_loc(block_addr);
            }
            Return | DirectJump | DirectCall => {}
        }
        Ok(())
    }

    fn on_prev_cached_key(&mut self, cached_key: Self::CachedKey) -> Result<(), Self::Error> {
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
                debug_assert!(bitmap_index <= u32::MAX as usize, "Bitmap size too large");
                self.per_cache_recorded_bitmap_indices
                    .push(bitmap_index as u32);
            }
            *count = count.wrapping_add(bitmap_entry.bitmap_count());
        }

        Ok(())
    }

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
            start_index <= u32::MAX as usize && end_index <= u32::MAX as usize,
            "Too many bitmap entries!"
        );
        let start_index = unsafe { NonZero::new_unchecked(start_index as u32) };
        let end_index = unsafe { NonZero::new_unchecked(end_index as u32) };

        Ok(Some(PerCacheBitmapEntries {
            start: start_index,
            end: end_index,
        }))
    }

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
                bitmap_index < self.fuzz_bitmap.as_ref().len(),
                "Unexpected OOB"
            );
            let count = unsafe { self.fuzz_bitmap.as_mut().get_unchecked_mut(bitmap_index) };
            *count = count.wrapping_add(bitmap_entry.bitmap_count());
        }
        self.set_new_loc(new_bb);

        Ok(())
    }
}

const DUMMY_BITMAP_ENTRY: CompactBitmapEntry = CompactBitmapEntry { value: 0 };

#[derive(Clone, Copy)]
struct CompactBitmapEntry {
    value: u32,
}

impl CompactBitmapEntry {
    fn new(bitmap_index: usize, bitmap_count: u8) -> Self {
        debug_assert!(bitmap_index <= 0x00FF_FFFF, "Bitmap size too large");
        let bitmap_index = bitmap_index as u32 & 0x00FF_FFFF;
        Self {
            value: bitmap_index | ((bitmap_count as u32) << 24),
        }
    }

    fn bitmap_index(self) -> usize {
        (self.value & 0x00FF_FFFF) as usize
    }

    fn bitmap_count(self) -> u8 {
        (self.value >> 24) as u8
    }
}

#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct PerCacheBitmapEntries {
    start: NonZero<u32>,
    end: NonZero<u32>,
}

impl PerCacheBitmapEntries {
    fn to_range(self) -> Range<usize> {
        (self.start.get() as usize)..(self.end.get() as usize)
    }
}
