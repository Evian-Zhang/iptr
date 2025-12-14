use hashbrown::{DefaultHashBuilder, HashMap, hash_map::Entry};

#[derive(Hash, PartialEq, Eq)]
enum CachedTnts {
    Dword([u8; 4]),
    Byte([u8; 1]),
}

#[doc(hidden)]
#[derive(Hash, PartialEq, Eq)]
pub struct ControlFlowSequence {
    start_bb: u64,
    cached_tnts: CachedTnts,
}

pub struct CachableInformation<D> {
    pub user_data: D,
}

pub struct ControlFlowCacheManager<D> {
    cache: HashMap<ControlFlowSequence, CachableInformation<D>>,
}

impl<D> Default for ControlFlowCacheManager<D> {
    fn default() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
}

type ControlFlowCacheEntry<'a, D> =
    Entry<'a, ControlFlowSequence, CachableInformation<D>, DefaultHashBuilder>;

impl<D> ControlFlowCacheManager<D> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_byte(&self, start_bb: u64, byte: u8) -> Option<&CachableInformation<D>> {
        self.cache.get(&ControlFlowSequence {
            start_bb,
            cached_tnts: CachedTnts::Byte([byte]),
        })
    }

    pub fn insert_byte(&mut self, start_bb: u64, byte: u8, info: CachableInformation<D>) {
        self.cache.insert(
            ControlFlowSequence {
                start_bb,
                cached_tnts: CachedTnts::Byte([byte]),
            },
            info,
        );
    }

    pub fn entry_of_byte(&mut self, start_bb: u64, byte: u8) -> ControlFlowCacheEntry<'_, D> {
        self.cache.entry(ControlFlowSequence {
            start_bb,
            cached_tnts: CachedTnts::Byte([byte]),
        })
    }

    pub fn get_dword(&self, start_bb: u64, dword: [u8; 4]) -> Option<&CachableInformation<D>> {
        self.cache.get(&ControlFlowSequence {
            start_bb,
            cached_tnts: CachedTnts::Dword(dword),
        })
    }

    pub fn insert_dword(&mut self, start_bb: u64, dword: [u8; 4], info: CachableInformation<D>) {
        self.cache.insert(
            ControlFlowSequence {
                start_bb,
                cached_tnts: CachedTnts::Dword(dword),
            },
            info,
        );
    }

    pub fn entry_of_dword(
        &mut self,
        start_bb: u64,
        dword: [u8; 4],
    ) -> ControlFlowCacheEntry<'_, D> {
        self.cache.entry(ControlFlowSequence {
            start_bb,
            cached_tnts: CachedTnts::Dword(dword),
        })
    }
}
