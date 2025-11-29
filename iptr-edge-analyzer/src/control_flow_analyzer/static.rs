use hashbrown::HashMap;

pub struct CfgNode {}

pub struct StaticControlFlowAnalyzer {
    cfg: HashMap<u64, CfgNode>,
}

impl StaticControlFlowAnalyzer {
    pub fn new() -> Self {
        Self {
            cfg: HashMap::new(),
        }
    }
}
