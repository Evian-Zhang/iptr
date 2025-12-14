pub enum ControlFlowTransitionKind {
    ConditionalBranch,
    DirectJump,
    DirectCall,
    IndirectJump,
    IndirectCall,
    Return,
}

pub trait HandleControlFlow {
    type Error: std::error::Error;
    type CachedKey: Copy;

    fn on_new_block(
        &mut self,
        block_addr: u64,
        transition_kind: ControlFlowTransitionKind,
    ) -> Result<Option<Self::CachedKey>, Self::Error>;

    fn on_reused_cache(&mut self, cached_key: Self::CachedKey) -> Result<(), Self::Error>;

    fn merge_cached_keys(
        &mut self,
        cached_key1: Self::CachedKey,
        cached_key2: Self::CachedKey,
    ) -> Result<Self::CachedKey, Self::Error>;
}
