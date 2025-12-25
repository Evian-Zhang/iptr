//! Control flow cache structures and algorithms

use hashbrown::HashMap;

/// Key structure for the 8bit cache hash map.
#[derive(Hash, PartialEq, Eq)]
struct ControlFlowSequence8 {
    /// Absolute address starting the TNT sequences
    start_bb: u64,
    /// 8 bits TNT sequences
    cached_tnts: [u8; 1],
}

/// Compact representation of trailing bits
///
/// The lower 8 bits are trailing bits itself (from MSB to LSB),
/// The upper 8 bits are number of bits
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct TrailingBits(u16);

impl TrailingBits {
    /// Create a new trailing bits
    ///
    /// The bits shall never exceed 7 bits
    #[expect(clippy::cast_possible_truncation)]
    pub fn new(remain_tnt_buffer: u32, remain_bits: u32) -> Self {
        debug_assert_eq!(
            remain_tnt_buffer & 0x00FF_FFFF,
            0,
            "remain tnt buffer exceeds 8 bits"
        );
        debug_assert!(remain_bits < 8, "remain bits >= 8");
        Self((remain_bits as u16) | ((remain_tnt_buffer >> 16) as u16))
    }
}

/// Key structure for the 8bit cache hash map.
#[derive(Hash, PartialEq, Eq)]
struct ControlFlowSequenceTrailBits {
    /// Absolute address starting the TNT sequences
    start_bb: u64,
    /// Trailing bits
    trailing_bits: TrailingBits,
}

/// Key structure for the 32bit cache hash map.
#[derive(Hash, PartialEq, Eq)]
struct ControlFlowSequence32 {
    /// Absolute address starting the TNT sequences
    start_bb: u64,
    /// 32 bits TNT sequences
    cached_tnts: [u8; 4],
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
    /// Internal 8bit cache structure, will become very large
    cache8: HashMap<ControlFlowSequence8, CachableInformation<D>>,
    /// Internal 32bit cache structure, will become very large
    cache32: HashMap<ControlFlowSequence32, CachableInformation<D>>,
    /// Internal trailing bits cache structure, will become very large
    cache_trailing_bits: HashMap<ControlFlowSequenceTrailBits, CachableInformation<D>>,
}

const CACHE_MAP_INITIAL_CAPACITY: usize = 0x100;

impl<D> Default for ControlFlowCacheManager<D> {
    fn default() -> Self {
        Self {
            cache8: HashMap::with_capacity(CACHE_MAP_INITIAL_CAPACITY),
            cache32: HashMap::with_capacity(CACHE_MAP_INITIAL_CAPACITY),
            cache_trailing_bits: HashMap::with_capacity(CACHE_MAP_INITIAL_CAPACITY),
        }
    }
}

impl<D> ControlFlowCacheManager<D> {
    /// Create a new [`ControlFlowCacheManager`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the size of trailing bits cache, 8bit cache and 32bit cache, respectively
    pub fn cache_size(&self) -> (usize, usize, usize) {
        (
            self.cache_trailing_bits.len(),
            self.cache8.len(),
            self.cache32.len(),
        )
    }

    /// Get cached information for 8 bits TNTs
    pub fn get_byte(&self, start_bb: u64, byte: u8) -> Option<&CachableInformation<D>> {
        self.cache8.get(&ControlFlowSequence8 {
            start_bb,
            cached_tnts: [byte],
        })
    }

    /// Set cache entry for 8 bits TNTs
    pub fn insert_byte(&mut self, start_bb: u64, byte: u8, info: CachableInformation<D>) {
        self.cache8.insert(
            ControlFlowSequence8 {
                start_bb,
                cached_tnts: [byte],
            },
            info,
        );
    }

    /// Get cached information for trailing TNT bits
    pub fn get_trailing_bits(
        &self,
        start_bb: u64,
        trailing_bits: TrailingBits,
    ) -> Option<&CachableInformation<D>> {
        self.cache_trailing_bits.get(&ControlFlowSequenceTrailBits {
            start_bb,
            trailing_bits,
        })
    }

    /// Set cache entry for trailing TNT bits
    pub fn insert_trailing_bits(
        &mut self,
        start_bb: u64,
        trailing_bits: TrailingBits,
        info: CachableInformation<D>,
    ) {
        self.cache_trailing_bits.insert(
            ControlFlowSequenceTrailBits {
                start_bb,
                trailing_bits,
            },
            info,
        );
    }

    /// Get cached information for 32 bits TNTs
    pub fn get_dword(&self, start_bb: u64, dword: [u8; 4]) -> Option<&CachableInformation<D>> {
        self.cache32.get(&ControlFlowSequence32 {
            start_bb,
            cached_tnts: dword,
        })
    }

    /// Set cache entry for 32 bits TNTs
    pub fn insert_dword(&mut self, start_bb: u64, dword: [u8; 4], info: CachableInformation<D>) {
        self.cache32.insert(
            ControlFlowSequence32 {
                start_bb,
                cached_tnts: dword,
            },
            info,
        );
    }
}
