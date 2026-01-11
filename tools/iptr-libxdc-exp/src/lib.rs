pub mod memory_reader;

#[cfg(all(not(feature = "debug"), feature = "diagnose"))]
use iptr_edge_analyzer::{
    DiagnosticInformation, EdgeAnalyzer,
    control_flow_handler::fuzz_bitmap::FuzzBitmapDiagnosticInformation,
};

#[cfg(all(not(feature = "debug"), feature = "diagnose"))]
pub fn report_diagnose(
    diagnostic_information: &DiagnosticInformation,
    fuzz_bitmap_diagnostic_information: &FuzzBitmapDiagnosticInformation,
) {
    let DiagnosticInformation {
        cfg_size,
        cache_trailing_bits_size,
        cache8_size,
        cache32_size,
        cache_32bit_hit_count,
        cache_8bit_hit_count,
        cache_trailing_bits_hit_count,
        cache_missed_bit_count,
    } = &diagnostic_information;
    let FuzzBitmapDiagnosticInformation {
        bitmap_entries_count,
    } = fuzz_bitmap_diagnostic_information;
    log::info!(
        "Analyzer diagnose statistics
CFG size {cfg_size}
Cache size
\t{cache_trailing_bits_size} trailing bits
\t{cache8_size} 8bits
\t{cache32_size} 32bits
Cache hitcount
\t{cache_trailing_bits_hit_count} trailing bits
\t{cache_8bit_hit_count} 8bits
\t{cache_32bit_hit_count} 32bits
\t{cache_missed_bit_count} missed
Fuzz bitmap
\t{bitmap_entries_count} raw bitmap entries
    "
    );
}
