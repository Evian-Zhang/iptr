use iptr_edge_analyzer::{ControlFlowTransitionKind, HandleControlFlow};

#[derive(Default)]
pub struct PerfAnalyzerControlFlowHandler {}

impl HandleControlFlow for PerfAnalyzerControlFlowHandler {
    type Error = std::convert::Infallible;
    type CachedKey = ();

    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn on_new_block(
        &mut self,
        _block_addr: u64,
        _transition_kind: ControlFlowTransitionKind,
    ) -> Result<Option<Self::CachedKey>, Self::Error> {
        Ok(None)
    }

    fn on_reused_cache(&mut self, _cached_key: &Self::CachedKey) -> Result<(), Self::Error> {
        Ok(())
    }

    fn merge_cached_keys(
        &mut self,
        _cached_key1: Self::CachedKey,
        _cached_key2: Self::CachedKey,
    ) -> Result<Self::CachedKey, Self::Error> {
        Ok(())
    }
}
