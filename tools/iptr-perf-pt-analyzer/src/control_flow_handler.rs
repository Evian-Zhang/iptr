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
        _cache: bool,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn cache_prev_cached_key(&mut self, _cached_key: Self::CachedKey) -> Result<(), Self::Error> {
        Ok(())
    }

    fn take_cache(&mut self) -> Result<Option<Self::CachedKey>, Self::Error> {
        Ok(Some(()))
    }

    fn clear_current_cache(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn on_reused_cache(
        &mut self,
        _cached_key: &Self::CachedKey,
        _new_bb: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn should_clear_all_cache(&mut self) -> Result<bool, Self::Error> {
        Ok(false)
    }
}
