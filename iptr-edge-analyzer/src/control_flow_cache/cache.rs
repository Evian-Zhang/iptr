//! Control flow cache structures and algorithms

use hashbrown::HashMap;

/// Type of cached TNT sequences
///
/// We have done a empirical data analysis for common
/// Intel PT traces, and found that the average length of TNT bits
/// between two TIP packets are 32 bits.
#[derive(Hash, PartialEq, Eq)]
enum CachedTnts {
    /// 32 bits TNT sequences
    Dword([u8; 4]),
    /// 8 bits TNT sequences
    Byte([u8; 1]),
}

/// Key structure for the cache hash map.
#[derive(Hash, PartialEq, Eq)]
struct ControlFlowSequence {
    /// Absolute address starting the TNT sequences
    start_bb: u64,
    /// 8/32 bits TNT sequences
    cached_tnts: CachedTnts,
}

/// Value structure for the cache hash map
pub struct CachableInformation<D> {
    /// User defined data for [`HandleControlFlow`][crate::HandleControlFlow]
    pub user_data: D,
    /// The next basic block address after processing cached TNT sequences
    pub new_bb: u64,
}

/// Manager for control flow caches.
///
/// By design, only continuous TNT bits that are not related to deferred TIPs
/// will be cached.
///
/// When querying the control flow manager, it is suggested that first we query the
/// total 32 bits TNTs, and if the cache misses, we then query every 8 bits TNTs.
/// After the four 8-bit TNTs are resolved, we construct the total 32 bits TNTs.
/// In this case, for every 32 bits TNTs, there will be five cached entries.
pub struct ControlFlowCacheManager<D> {
    /// Internal cache structure, will become very large
    cache: HashMap<ControlFlowSequence, CachableInformation<D>>,
}

impl<D> Default for ControlFlowCacheManager<D> {
    fn default() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
}

impl<D> ControlFlowCacheManager<D> {
    /// Create a new [`ControlFlowCacheManager`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get cached information for 8 bits TNTs
    pub fn get_byte(&self, start_bb: u64, byte: u8) -> Option<&CachableInformation<D>> {
        self.cache.get(&ControlFlowSequence {
            start_bb,
            cached_tnts: CachedTnts::Byte([byte]),
        })
    }

    /// Set cache entry for 8 bits TNTs
    pub fn insert_byte(&mut self, start_bb: u64, byte: u8, info: CachableInformation<D>) {
        self.cache.insert(
            ControlFlowSequence {
                start_bb,
                cached_tnts: CachedTnts::Byte([byte]),
            },
            info,
        );
    }

    /// Get cached information for 32 bits TNTs
    pub fn get_dword(&self, start_bb: u64, dword: [u8; 4]) -> Option<&CachableInformation<D>> {
        self.cache.get(&ControlFlowSequence {
            start_bb,
            cached_tnts: CachedTnts::Dword(dword),
        })
    }

    /// Set cache entry for 32 bits TNTs
    pub fn insert_dword(&mut self, start_bb: u64, dword: [u8; 4], info: CachableInformation<D>) {
        self.cache.insert(
            ControlFlowSequence {
                start_bb,
                cached_tnts: CachedTnts::Dword(dword),
            },
            info,
        );
    }
}
