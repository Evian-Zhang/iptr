//! Module handling diagnostic information.

use crate::{EdgeAnalyzer, HandleControlFlow, ReadMemory};

/// Diagnostic information for [`EdgeAnalyzer`].
///
/// This struct can be retrieved from [`EdgeAnalyzer::diagnose`]
pub struct DiagnosticInformation {
    /// Size of CFG graph, i.e., number of nodes
    pub cfg_size: usize,
    /// Size of trailing bits cache, i.e., number of entries
    #[cfg(feature = "cache")]
    pub cache_trailing_bits_size: usize,
    /// Size of 8bit cache, i.e., number of entries
    #[cfg(feature = "cache")]
    pub cache8_size: usize,
    /// Size of 32bit cache, i.e., number of entries
    #[cfg(feature = "cache")]
    pub cache32_size: usize,
    /// Count of trailing bits cache hit
    #[cfg(all(feature = "cache", feature = "more_diagnose"))]
    pub cache_trailing_bits_hit_count: usize,
    /// Count of 8bit cache hit
    #[cfg(all(feature = "cache", feature = "more_diagnose"))]
    pub cache_8bit_hit_count: usize,
    /// Count of 32bit cache hit
    #[cfg(all(feature = "cache", feature = "more_diagnose"))]
    pub cache_32bit_hit_count: usize,
    /// Count of missed cache hit, i.e., directly CFG resolution
    #[cfg(all(feature = "cache", feature = "more_diagnose"))]
    pub cache_missed_bit_count: usize,
}

impl<H: HandleControlFlow, R: ReadMemory> EdgeAnalyzer<H, R> {
    /// Get diagnostic information
    #[must_use]
    pub fn diagnose(&self) -> DiagnosticInformation {
        let cfg_size = self.static_analyzer.cfg_size();
        #[cfg(feature = "cache")]
        let (cache_trailing_bits_size, cache8_size, cache32_size) = self.cache_manager.cache_size();

        DiagnosticInformation {
            cfg_size,
            #[cfg(feature = "cache")]
            cache_trailing_bits_size,
            #[cfg(feature = "cache")]
            cache8_size,
            #[cfg(feature = "cache")]
            cache32_size,
            #[cfg(all(feature = "cache", feature = "more_diagnose"))]
            cache_32bit_hit_count: self.cache_32bit_hit_count,
            #[cfg(all(feature = "cache", feature = "more_diagnose"))]
            cache_8bit_hit_count: self.cache_8bit_hit_count,
            #[cfg(all(feature = "cache", feature = "more_diagnose"))]
            cache_trailing_bits_hit_count: self.cache_trailing_bits_hit_count,
            #[cfg(all(feature = "cache", feature = "more_diagnose"))]
            cache_missed_bit_count: self.cache_missed_bit_count,
        }
    }
}
