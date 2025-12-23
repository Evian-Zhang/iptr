use crate::{EdgeAnalyzer, HandleControlFlow, ReadMemory};

/// Diagnostic information for [`EdgeAnalyzer`].
///
/// This struct can be retrieved from [`EdgeAnalyzer::diagnose`]
pub struct DiagnosticInformation {
    /// Size of CFG graph, i.e., number of nodes
    pub cfg_size: usize,
    /// Size of 8bit cache, i.e., number of entries
    #[cfg(feature = "cache")]
    pub cache8_size: usize,
    /// Size of 32bit cache, i.e., number of entries
    #[cfg(feature = "cache")]
    pub cache32_size: usize,
    /// Count of 8bit cache hit
    #[cfg(feature = "cache")]
    pub cache_8bit_hit_count: usize,
    /// Count of 32bit cache hit
    #[cfg(feature = "cache")]
    pub cache_32bit_hit_count: usize,
    /// Count of missed cache hit, i.e., directly CFG resolution
    #[cfg(feature = "cache")]
    pub cache_missed_bit_count: usize,
    /// Ratio of cache hit
    #[cfg(feature = "cache")]
    pub cache_hit_ratio: f64,
}

impl<H: HandleControlFlow, R: ReadMemory> EdgeAnalyzer<'_, H, R> {
    /// Get diagnostic information
    #[must_use]
    pub fn diagnose(&self) -> DiagnosticInformation {
        let cfg_size = self.static_analyzer.cfg_size();
        #[cfg(feature = "cache")]
        let (cache8_size, cache32_size) = self.cache_manager.cache_size();
        #[cfg(feature = "cache")]
        let cache_hit_ratio = {
            let cache_hit_count = self
                .cache_32bit_hit_count
                .saturating_mul(32)
                .saturating_add(self.cache_8bit_hit_count.saturating_mul(8));
            let total_bit_count = cache_hit_count.saturating_add(self.cache_missed_bit_count);
            cache_hit_count as f64 / total_bit_count as f64
        };

        DiagnosticInformation {
            cfg_size,
            #[cfg(feature = "cache")]
            cache8_size,
            #[cfg(feature = "cache")]
            cache32_size,
            #[cfg(feature = "cache")]
            cache_32bit_hit_count: self.cache_32bit_hit_count,
            #[cfg(feature = "cache")]
            cache_8bit_hit_count: self.cache_8bit_hit_count,
            #[cfg(feature = "cache")]
            cache_missed_bit_count: self.cache_missed_bit_count,
            #[cfg(feature = "cache")]
            cache_hit_ratio,
        }
    }
}
