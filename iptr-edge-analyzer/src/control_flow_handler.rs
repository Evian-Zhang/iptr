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
    type CachedKey;

    fn on_new_block(
        &mut self,
        block_addr: u64,
        transition_kind: ControlFlowTransitionKind,
    ) -> Result<(), Self::Error>;
}
