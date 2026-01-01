//! This module contains the core definition of [`HandleControlFlow`] trait,
//! and several implementors like [`FuzzBitmapControlFlowHandler`][fuzz_bitmap::FuzzBitmapControlFlowHandler].

pub mod combined;
#[cfg(feature = "fuzz_bitmap")]
pub mod fuzz_bitmap;

/// Kind of control flow transitions
#[derive(Debug, Clone, Copy)]
pub enum ControlFlowTransitionKind {
    /// Conditional Jcc
    ConditionalBranch,
    /// Direct JMP
    DirectJump,
    /// Direct CALL
    DirectCall,
    /// Indirect transition
    Indirect,
    /// New block
    ///
    /// Basic blocks that cannot be categorized into
    /// other reasons
    NewBlock,
}

/// Control flow handler used for [`EdgeAnalyzer`][crate::EdgeAnalyzer]
///
/// There are several implementors provided in this crate, such as
/// [`FuzzBitmapControlFlowHandler`][fuzz_bitmap::FuzzBitmapControlFlowHandler].
///
/// The overall workflow when using this trait is like:
/// 1. Creating a new handler.
/// 2. Clear cache by [`clear_current_cache`][HandleControlFlow::clear_current_cache]
/// 3. When a new basic block is met, call [`on_new_block`][HandleControlFlow::on_new_block].
///    This function should always deal with the impact, and deal with the cache depending on the
///    `cache` parameter.
/// 4. When a previous cache is met, call [`on_reused_cache`][HandleControlFlow::on_reused_cache].
///    This function should only deal with the impact.
/// 5. Optionally merge caches by [`cache_prev_cached_key`][HandleControlFlow::cache_prev_cached_key].
/// 6. Collect cache by [`take_cache`][HandleControlFlow::take_cache].
///
/// In the documentation of this trait, there are two terms: "impact" and "cache". Let's take
/// some examples. For fuzzing, "impact" means modification of fuzzing bitmap, and "cache"
/// means modification of internal cached information. For logging, "impact" means logging the
/// basic block transition, and "cache" also means the modification of internal cached information.
pub trait HandleControlFlow {
    /// Error of control flow handler
    type Error: std::error::Error;
    /// Cached key returned by [`on_new_block`][HandleControlFlow::take_cache].
    ///
    /// This can be used by the edge analyzer to tell the control flow handler
    /// a previous TNT sequence has been met again and the cache is reused instead
    /// of re-parsing all TNT bits.
    #[cfg(feature = "cache")]
    type CachedKey: Clone;

    /// Callback at begin of decoding.
    ///
    /// This is useful when using the same handler to process multiple Intel PT
    /// traces
    fn at_decode_begin(&mut self) -> Result<(), Self::Error>;

    /// Callback when a new basic block is met.
    ///
    /// The new block's address is `block_addr`, and the reason for getting
    /// into this block is in `transition_kind`. `cache` indicates whether this
    /// block transition should be taken into cache by the implementor, which is
    /// used as an optimizing hint. If `cache` is false, this means this transition
    /// will never be folded into cache. No matter `cache` is true or false, this
    /// function should always deal with the impact of new block.
    ///
    /// When conducting caching, it should be extremely important, that
    /// the cached state should always be consistent with `block_addr`.
    ///
    /// Suggest marking `#[inline]` on the implementation
    fn on_new_block(
        &mut self,
        block_addr: u64,
        transition_kind: ControlFlowTransitionKind,
        cache: bool,
    ) -> Result<(), Self::Error>;

    /// Merge a previous cached key into cache
    ///
    /// When analyzing TNT packets, the cache manager maintains two kinds of cache: 8bits cache
    /// and 32bits cache. As a result, when creating 32bits caches, we need to merge four 8bits
    /// caches into one 32bits cache, and this function serves the purpose.
    ///
    /// It should be noted that although merged, the previous cache should still be kept.
    ///
    /// This function only deals with the caching thing. The previously cached information should
    /// not have impact in this function. For dealing with impacts, see [`on_reused_cache`][HandleControlFlow::on_reused_cache].
    #[cfg(feature = "cache")]
    fn cache_prev_cached_key(&mut self, cached_key: Self::CachedKey) -> Result<(), Self::Error>;

    /// Collect all currently cached information and generate a cached key. This could clear
    /// the cache depending on your implementing logic.
    ///
    /// If there is no cache, this function should return `Ok(None)`.
    #[cfg(feature = "cache")]
    fn take_cache(&mut self) -> Result<Option<Self::CachedKey>, Self::Error>;

    /// Clear the cache.
    ///
    /// This is NOT clearing all cached information. Instead, this is
    /// to clear current temporary cache.
    #[cfg(feature = "cache")]
    fn clear_current_cache(&mut self) -> Result<(), Self::Error>;

    /// Callback when a given cached key is being reused.
    ///
    /// `new_bb` is the next basic block address after the cached key is applied.
    ///
    /// This function only deals ith the impact of cached key, and should not add new caches.
    /// For adding new caches, see [`cache_prev_cached_key`][HandleControlFlow::cache_prev_cached_key].
    #[cfg(feature = "cache")]
    fn on_reused_cache(
        &mut self,
        cached_key: &Self::CachedKey,
        new_bb: u64,
    ) -> Result<(), Self::Error>;
}
