use std::{fs::File, io::BufWriter, path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::ProgressIterator;
use iptr_decoder::DecodeOptions;
#[cfg(all(not(feature = "debug"), feature = "diagnose"))]
use iptr_edge_analyzer::{
    DiagnosticInformation, EdgeAnalyzer,
    control_flow_handler::fuzz_bitmap::FuzzBitmapDiagnosticInformation,
};
use iptr_edge_analyzer::{
    EdgeAnalyzer, control_flow_handler::fuzz_bitmap::FuzzBitmapControlFlowHandler,
};
use iptr_libxdc_exp::memory_reader::MemoryReader;
use serde::Serialize;

/// A standalone binary for libxdc-like evaluation
///
/// This program will decode Intel PT traces of seeds generated
/// when fuzzing, targeting at testing the performance in fuzzing.
///
/// This binary implements memory reader compatible of
/// that in libxdc_experiments.
///
/// Set the environment variable `RUST_LOG=trace` for logging.
#[derive(Parser)]
struct Cmdline {
    /// Path to a directory containing PT traces of fuzzing seeds.
    ///
    /// Each file inside the target directory should have filename
    /// "index.bin", where "index" is counted from 0, and is continuous.
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
    /// Max index of files inside PT traces directory.
    ///
    /// Note that for performance consideration, all files within
    /// the max index will be read into memory at the same time,
    /// so consider decrease the number if you have a relatively
    /// small RAM.
    #[arg(long)]
    max_index: usize,
    /// Path for statistics output
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Serialize)]
struct StatisticsOutput {
    total_time: u128,
    times: Vec<u128>,
}

fn main() -> Result<()> {
    env_logger::init();

    let Cmdline {
        input,
        page_dump,
        page_addr,
        range_start,
        range_end,
        max_index,
        output,
    } = Cmdline::parse();

    let range = iptr_libxdc_exp::extract_range(range_start, range_end)?;

    let mut bitmap = vec![0u8; 0x10000].into_boxed_slice();

    let memory_reader =
        MemoryReader::new(&page_dump, &page_addr).context("Failed to create memory reader")?;
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

    let mut times = Vec::with_capacity(max_index);
    let mut pt_traces = Vec::with_capacity(max_index);
    for index in 0..=max_index {
        let input_path = input.join(format!("{index}.pt"));
        pt_traces.push(std::fs::read(&input_path).context(format!(
            "Failed to read {} in input directory",
            input_path.display()
        ))?);
    }

    let instant = Instant::now();
    for pt_trace in pt_traces.into_iter().progress() {
        iptr_decoder::decode(&pt_trace, DecodeOptions::default(), &mut packet_handler).unwrap();
        let time = instant.elapsed();
        let time = time.as_nanos();
        times.push(time);

        #[cfg(all(not(feature = "debug"), feature = "diagnose"))]
        iptr_libxdc_exp::report_diagnose(
            &packet_handler.diagnose(),
            &packet_handler.handler().diagnose(),
        );
    }
    let total_time = instant.elapsed();
    let total_time = total_time.as_nanos();
    let statistics_output = StatisticsOutput { total_time, times };
    serde_json::to_writer(
        BufWriter::new(File::create(output).context("Failed to create output file")?),
        &statistics_output,
    )
    .context("Failed to serialize statistics output into output file")?;

    Ok(())
}
