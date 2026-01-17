pub mod memory_reader;

use anyhow::{Context, Result};
#[cfg(all(not(feature = "debug"), feature = "diagnose"))]
use iptr_edge_analyzer::{
    DiagnosticInformation, control_flow_handler::fuzz_bitmap::FuzzBitmapDiagnosticInformation,
};

pub fn extract_range(
    range_start: Option<String>,
    range_end: Option<String>,
) -> Result<Option<[(u64, u64); 1]>> {
    match (range_start, range_end) {
        (Some(start), Some(end)) => {
            let start = start.strip_prefix("0x").unwrap_or(&start);
            let start = u64::from_str_radix(start, 16).context("Invalid --range-start")?;

            let end = end.strip_prefix("0x").unwrap_or(&end);
            let end = u64::from_str_radix(end, 16).context("Invalid --range-start")?;

            Ok(Some([(start, end)]))
        }
        (None, None) => Ok(None),
        _ => Err(anyhow::anyhow!(
            "--range-start and --range-end should be given at the same time"
        )),
    }
}

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
