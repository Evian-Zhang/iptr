use iptr_edge_analyzer::{ControlFlowTransitionKind, HandleControlFlow};

#[derive(Default)]
pub struct FuzzBitmapControlFlowHandler {}

impl HandleControlFlow for FuzzBitmapControlFlowHandler {
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
