//! This module contains combined control flow handler logics.

use crate::HandleControlFlow;

use perfect_derive::perfect_derive;
use thiserror::Error;

/// A [`HandleControlFlow`] instance for combining two sub handlers
pub struct CombinedControlFlowHandler<H1, H2>
where
    H1: HandleControlFlow,
    H2: HandleControlFlow,
{
    handler1: H1,
    handler2: H2,
}

impl<H1, H2> CombinedControlFlowHandler<H1, H2>
where
    H1: HandleControlFlow,
    H2: HandleControlFlow,
{
    /// Create a new [`CombinedControlFlowHandler`]
    #[must_use]
    pub fn new(handler1: H1, handler2: H2) -> Self {
        Self { handler1, handler2 }
    }

    /// Consume the handler and get the original two handler
    pub fn into_inner(self) -> (H1, H2) {
        (self.handler1, self.handler2)
    }

    /// Get shared reference to handler1
    pub fn handler1(&self) -> &H1 {
        &self.handler1
    }

    /// Get unique reference to handler1
    pub fn handler1_mut(&mut self) -> &mut H1 {
        &mut self.handler1
    }

    /// Get shared reference to handler2
    pub fn handler2(&self) -> &H2 {
        &self.handler2
    }

    /// Get unique reference to handler2
    pub fn handler2_mut(&mut self) -> &mut H2 {
        &mut self.handler2
    }
}

/// Error for [`CombinedControlFlowHandler`]
#[derive(Error)]
#[perfect_derive(Debug)]
pub enum CombinedError<H1, H2>
where
    H1: HandleControlFlow,
    H2: HandleControlFlow,
{
    /// Error of the first handler
    #[error(transparent)]
    H1Error(H1::Error),
    /// Error of the second handler
    #[error(transparent)]
    H2Error(H2::Error),
}

impl<H1, H2> HandleControlFlow for CombinedControlFlowHandler<H1, H2>
where
    H1: HandleControlFlow,
    H2: HandleControlFlow,
{
    type Error = CombinedError<H1, H2>;

    #[cfg(feature = "cache")]
    type CachedKey = (Option<H1::CachedKey>, Option<H2::CachedKey>);

    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        self.handler1
            .at_decode_begin()
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .at_decode_begin()
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_new_block(
        &mut self,
        block_addr: u64,
        transition_kind: super::ControlFlowTransitionKind,
        cache: bool,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_new_block(block_addr, transition_kind, cache)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_new_block(block_addr, transition_kind, cache)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    #[cfg(feature = "cache")]
    fn cache_prev_cached_key(
        &mut self,
        (cached_key1, cached_key2): Self::CachedKey,
    ) -> Result<(), Self::Error> {
        if let Some(cached_key) = cached_key1 {
            self.handler1
                .cache_prev_cached_key(cached_key)
                .map_err(CombinedError::H1Error)?;
        }
        if let Some(cached_key) = cached_key2 {
            self.handler2
                .cache_prev_cached_key(cached_key)
                .map_err(CombinedError::H2Error)?;
        }

        Ok(())
    }

    #[cfg(feature = "cache")]
    fn take_cache(&mut self) -> Result<Option<Self::CachedKey>, Self::Error> {
        let cached_key1 = self.handler1.take_cache().map_err(CombinedError::H1Error)?;
        let cached_key2 = self.handler2.take_cache().map_err(CombinedError::H2Error)?;

        Ok(Some((cached_key1, cached_key2)))
    }

    #[cfg(feature = "cache")]
    fn clear_current_cache(&mut self) -> Result<(), Self::Error> {
        self.handler1
            .clear_current_cache()
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .clear_current_cache()
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    #[cfg(feature = "cache")]
    fn on_reused_cache(
        &mut self,
        (cached_key1, cached_key2): &Self::CachedKey,
        new_bb: u64,
    ) -> Result<(), Self::Error> {
        if let Some(cached_key) = cached_key1 {
            self.handler1
                .on_reused_cache(cached_key, new_bb)
                .map_err(CombinedError::H1Error)?;
        }
        if let Some(cached_key) = cached_key2 {
            self.handler2
                .on_reused_cache(cached_key, new_bb)
                .map_err(CombinedError::H2Error)?;
        }

        Ok(())
    }

    /// In combined control flow handler, this function is special since
    /// it is possible that one of the two handlers wants to clear
    /// all caches while the other does not.
    ///
    /// In this case (any of the two sub handlers want to clear cache),
    /// the function will return `true`. The invalidation of cached keys
    /// should not affect the correctness of handlers. So even if another
    /// handler does not want to clear cache, it should still work correctly.
    #[cfg(feature = "cache")]
    fn should_clear_all_cache(&mut self) -> Result<bool, Self::Error> {
        let should_clear1 = self
            .handler1
            .should_clear_all_cache()
            .map_err(CombinedError::H1Error)?;
        let should_clear2 = self
            .handler2
            .should_clear_all_cache()
            .map_err(CombinedError::H2Error)?;

        Ok(should_clear1 || should_clear2)
    }
}
