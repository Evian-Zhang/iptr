use crate::{ControlFlowTransitionKind, HandleControlFlow};

pub struct FuzzBitmapControlFlowHandler {
    per_cache_recorded_bitmap_indices: Vec<u32>,
    per_cache_bitmap: Box<[u8]>,
    fuzz_bitmap: Box<[u8]>,
    prev_loc: u64,
}

const INITIAL_RESULTS_PER_CACHE: usize = 64;

impl FuzzBitmapControlFlowHandler {
    pub fn new(bitmap_size: usize) -> Self {
        Self {
            per_cache_recorded_bitmap_indices: Vec::with_capacity(INITIAL_RESULTS_PER_CACHE),
            per_cache_bitmap: vec![0u8; bitmap_size].into_boxed_slice(),
            fuzz_bitmap: vec![0u8; bitmap_size].into_boxed_slice(),
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

impl HandleControlFlow for FuzzBitmapControlFlowHandler {
    type Error = std::convert::Infallible;
    type CachedKey = ();

    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
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
            ConditionalBranch => todo!(),
            DirectJump => todo!(),
            DirectCall => todo!(),
            IndirectJump => todo!(),
            IndirectCall => todo!(),
            Return => todo!(),
            FarTransfer => todo!(),
            NewBlock => todo!(),
        }
        Ok(())
    }

    fn on_reusing_cached_key(&mut self, _cached_key: Self::CachedKey) -> Result<(), Self::Error> {
        Ok(())
    }

    fn take_cache(&mut self) -> Result<Option<Self::CachedKey>, Self::Error> {
        Ok(Some(()))
    }

    fn on_reused_cache(&mut self, _cached_key: &Self::CachedKey) -> Result<(), Self::Error> {
        Ok(())
    }
}
