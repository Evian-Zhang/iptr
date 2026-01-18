use std::{fs::File, path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use clap::Parser;
use iptr_decoder::DecodeOptions;
use iptr_edge_analyzer::{
    EdgeAnalyzer, control_flow_handler::fuzz_bitmap::FuzzBitmapControlFlowHandler,
    memory_reader::libxdc::LibxdcMemoryReader,
};

/// A standalone binary for libxdc-like evaluation
///
/// This program will decode the same Intel PT trace multiple times,
/// targeting at testing the performance of cache querying.
///
/// This binary implements memory reader compatible of
/// that in libxdc_experiments.
///
/// Set the environment variable `RUST_LOG=trace` for logging.
#[derive(Parser)]
struct Cmdline {
    /// Path to pure Intel PT data
    #[arg(short, long)]
    input: PathBuf,
    /// Path to page dump file
    #[arg(long)]
    page_dump: PathBuf,
    /// Path to page addr file
    #[arg(long)]
    page_addr: PathBuf,
    /// Start address of filter range, if given.
    ///
    /// For instructions out of the filter range, the fuzzing
    /// bitmap will not be updated.
    ///
    /// You should pass --range-start and --range-end at
    /// the same time.
    #[arg(long)]
    range_start: Option<String>,
    /// End address of filter range, if given.
    ///
    /// For instructions out of the filter range, the fuzzing
    /// bitmap will not be updated.
    ///
    /// You should pass --range-start and --range-end at
    /// the same time.
    #[arg(long)]
    range_end: Option<String>,
    /// Number of round for repeated evaluation.
    ///
    /// The value should be greater than 1.
    #[arg(long)]
    round: usize,
}

#[expect(clippy::cast_precision_loss)]
fn main() -> Result<()> {
    env_logger::init();

    let Cmdline {
        input,
        page_dump,
        page_addr,
        range_start,
        range_end,
        round,
    } = Cmdline::parse();

    let range = iptr_libxdc_exp::extract_range(range_start, range_end)?;

    let mut bitmap = vec![0u8; 0x10000].into_boxed_slice();

    let memory_reader = LibxdcMemoryReader::new(&page_dump, &page_addr)
        .context("Failed to create memory reader")?;
    let control_flow_handler =
        FuzzBitmapControlFlowHandler::new(bitmap.as_mut(), range.as_ref().map(<[_; _]>::as_slice));
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

    let instant = Instant::now();
    iptr_decoder::decode(&buf, DecodeOptions::default(), &mut packet_handler).unwrap();
    let cold_time = instant.elapsed();
    log::info!("run_time_cold = {}", cold_time.as_nanos());
    #[cfg(all(not(feature = "debug"), feature = "diagnose"))]
    iptr_libxdc_exp::report_diagnose(
        &packet_handler.diagnose(),
        &packet_handler.handler().diagnose(),
    );

    if round <= 1 {
        return Err(anyhow::anyhow!("--round should be greater than 1"));
    }

    let round = round - 1;
    let mut total_time = 0;
    for _ in 0..round {
        let instant = Instant::now();
        iptr_decoder::decode(&buf, DecodeOptions::default(), &mut packet_handler).unwrap();
        let time = instant.elapsed();
        let time = time.as_nanos();
        total_time += time;
        log::info!("run_time = {time}");

        #[cfg(all(not(feature = "debug"), feature = "diagnose"))]
        iptr_libxdc_exp::report_diagnose(
            &packet_handler.diagnose(),
            &packet_handler.handler().diagnose(),
        );
    }
    log::info!("avg_time = {}", total_time as f64 / round as f64);

    Ok(())
}
