use hashbrown::HashMap;

#[derive(Hash, PartialEq, Eq)]
enum CachedTnts {
    Qword([u8; 8]),
    Dword([u8; 4]),
    Word([u8; 2]),
    Byte([u8; 1]),
}

#[derive(Hash, PartialEq, Eq)]
struct ControlFlowSequence {
    start_bb: u64,
    cached_tnts: CachedTnts,
}

pub struct CachableInformation<D> {
    user_data: D,
}

pub struct ControlFlowCacheManager<D> {
    cache: HashMap<ControlFlowSequence, CachableInformation<D>>,
}
