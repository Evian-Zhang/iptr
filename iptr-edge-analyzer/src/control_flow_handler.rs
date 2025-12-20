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

    /// Callback when a new basic block is met.
    ///
    /// If the new block is not important, you can return [`None`] for cached key.
    fn on_new_block(
        &mut self,
        block_addr: u64,
        transition_kind: ControlFlowTransitionKind,
    ) -> Result<Option<Self::CachedKey>, Self::Error>;

    /// Callback when a given cached key is being reused.
    fn on_reused_cache(&mut self, cached_key: &Self::CachedKey) -> Result<(), Self::Error>;

    /// Merge two cached key into a new cached key.
    ///
    /// This is used when we merge two continuous cache into one longer cache.
    fn merge_cached_keys(
        &mut self,
        cached_key1: Self::CachedKey,
        cached_key2: Self::CachedKey,
    ) -> Result<Self::CachedKey, Self::Error>;
}
