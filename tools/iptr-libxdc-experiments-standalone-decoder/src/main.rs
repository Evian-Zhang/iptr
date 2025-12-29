mod memory_reader;

use std::{fs::File, path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use clap::Parser;
use iptr_decoder::DecodeOptions;
use iptr_edge_analyzer::{
    DiagnosticInformation, EdgeAnalyzer,
    control_flow_handler::fuzz_bitmap::{
        FuzzBitmapControlFlowHandler, FuzzBitmapDiagnosticInformation,
    },
};

use crate::memory_reader::MemoryReader;

#[derive(Parser)]
struct Cmdline {
    #[arg(short, long)]
    input: PathBuf,
    #[arg(long)]
    page_dump: PathBuf,
    #[arg(long)]
    page_addr: PathBuf,
    #[arg(long)]
    round: Option<usize>,
}

#[expect(clippy::cast_precision_loss)]
fn main() -> Result<()> {
    env_logger::init();

    let Cmdline {
        input,
        page_dump,
        page_addr,
        round,
    } = Cmdline::parse();

    let mut bitmap = vec![0u8; 0x10000].into_boxed_slice();

    let memory_reader =
        MemoryReader::new(&page_dump, &page_addr).context("Failed to create memory reader")?;
    let control_flow_handler = FuzzBitmapControlFlowHandler::new(bitmap.as_mut());
    let edge_analyzer = EdgeAnalyzer::new(control_flow_handler, memory_reader);
    #[cfg(feature = "debug")]
    let mut packet_handler = iptr_decoder::packet_handler::combined::CombinedPacketHandler::new(
        iptr_decoder::packet_handler::log::PacketHandlerRawLogger::default(),
        edge_analyzer,
    );
    #[cfg(not(feature = "debug"))]
    let mut packet_handler = edge_analyzer;

    let file = File::open(input).context("Failed to open input file")?;
    // SAFETY: check the safety requirements of memmap2 documentation
    let buf = unsafe { memmap2::Mmap::map(&file).context("Failed to mmap input file")? };

    if let Some(round) = round {
        if round <= 1 {
            return Err(anyhow::anyhow!("Round should be larger than 1"));
        }

        let instant = Instant::now();
        iptr_decoder::decode(&buf, DecodeOptions::default(), &mut packet_handler).unwrap();
        let cold_time = instant.elapsed();
        log::info!("run_time_cold = {}", cold_time.as_nanos());
        #[cfg(not(feature = "debug"))]
        report_diagnose(
            &packet_handler.diagnose(),
            &packet_handler.handler().diagnose(),
        );

        let round = round - 1;
        let mut total_time = 0;
        for _ in 0..round {
            let instant = Instant::now();
            iptr_decoder::decode(&buf, DecodeOptions::default(), &mut packet_handler).unwrap();
            let time = instant.elapsed();
            let time = time.as_nanos();
            total_time += time;
            log::info!("run_time = {time}");

            #[cfg(not(feature = "debug"))]
            report_diagnose(
                &packet_handler.diagnose(),
                &packet_handler.handler().diagnose(),
            );
        }
        log::info!("avg_time = {}", total_time as f64 / round as f64);
    } else {
        iptr_decoder::decode(&buf, DecodeOptions::default(), &mut packet_handler).unwrap();

        #[cfg(not(feature = "debug"))]
        report_diagnose(
            &packet_handler.diagnose(),
            &packet_handler.handler().diagnose(),
        );
    }

    Ok(())
}

#[allow(unused)]
fn report_diagnose(
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
