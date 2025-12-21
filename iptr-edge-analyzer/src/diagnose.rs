use crate::{EdgeAnalyzer, HandleControlFlow, ReadMemory};

/// Diagnostic information for [`EdgeAnalyzer`].
///
/// This struct can be retrieved from [`EdgeAnalyzer::diagnose`]
pub struct DiagnosticInformation {
    /// Size of CFG graph, i.e., number of nodes
    pub cfg_size: usize,
    /// Size of 8bit cache, i.e., number of entries
    pub cache8_size: usize,
    /// Size of 32bit cache, i.e., number of entries
    pub cache32_size: usize,
}

impl<H: HandleControlFlow, R: ReadMemory> EdgeAnalyzer<'_, H, R> {
    /// Get diagnostic information
    #[must_use]
    pub fn diagnose(&self) -> DiagnosticInformation {
        let cfg_size = self.static_analyzer.cfg_size();
        let (cache8_size, cache32_size) = self.cache_manager.cache_size();

        DiagnosticInformation {
            cfg_size,
            cache8_size,
            cache32_size,
        }
    }
}
