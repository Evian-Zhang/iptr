#[cfg(feature = "fuzz_bitmap")]
pub mod fuzz_bitmap;

/// Kind of control flow transitions
#[derive(Debug)]
pub enum ControlFlowTransitionKind {
    /// Conditional Jcc
    ConditionalBranch,
    /// Direct JMP
    DirectJump,
    /// Direct CALL
    DirectCall,
    /// Indirect JMP
    IndirectJump,
    /// Indirect CALL
    IndirectCall,
    /// RET
    Return,
    /// Far transfers
    FarTransfer,
    /// New block
    ///
    /// Basic blocks that cannot be categorized into
    /// other reasons
    NewBlock,
}

/// Control flow handler used for [`EdgeAnalyzer`][crate::EdgeAnalyzer]
pub trait HandleControlFlow {
    /// Error of control flow handler
    type Error: std::error::Error;
    /// Cached key returned by [`on_new_block`][HandleControlFlow::on_new_block].
    ///
    /// This can be used by the edge analyzer to tell the control flow handler
    /// a previous TNT sequence has been met again and the cache is reused instead
    /// of re-parsing all TNT bits.
    type CachedKey: Clone;

    /// Callback at begin of decoding.
    ///
    /// This is useful when using the same handler to process multiple Intel PT
    /// traces
    fn at_decode_begin(&mut self) -> Result<(), Self::Error>;

    /// Callback when a new basic block is met.
    ///
    /// Suggest marking `#[inline]` on the implementation
    fn on_new_block(
        &mut self,
        block_addr: u64,
        transition_kind: ControlFlowTransitionKind,
        cache: bool,
    ) -> Result<(), Self::Error>;

    /// Merge two cached key into a new cached key.
    ///
    /// This is used when we merge two continuous cache into one longer cache.
    fn on_prev_cached_key(&mut self, cached_key: Self::CachedKey) -> Result<(), Self::Error>;

    fn take_cache(&mut self) -> Result<Option<Self::CachedKey>, Self::Error>;

    /// Callback when a given cached key is being reused.
    fn on_reused_cache(
        &mut self,
        cached_key: &Self::CachedKey,
        new_bb: u64,
    ) -> Result<(), Self::Error>;
}
