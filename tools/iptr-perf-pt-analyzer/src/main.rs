mod control_flow_handler;

use anyhow::{Context, Result};
use clap::Parser;
use iptr_decoder::DecodeOptions;
use iptr_edge_analyzer::EdgeAnalyzer;
use iptr_perf_pt_reader::memory_reader::PerfMmapBasedMemoryReader;

use std::{fs::File, path::PathBuf};

/// Decode the Intel PT trace with semantic validation.
///
/// Set the environment variable `RUST_LOG=trace` for logging.
#[derive(Parser)]
struct Cmdline {
    /// Path of intel PT trace in perf.data format
    #[arg(short, long)]
    input: PathBuf,
}

fn main() -> Result<()> {
    env_logger::init();

    let Cmdline { input } = Cmdline::parse();

    let file = File::open(input).context("Failed to open input file")?;
    // SAFETY: check the safety requirements of memmap2 documentation
    let buf = unsafe { memmap2::Mmap::map(&file).context("Failed to mmap input file")? };

    let (pt_auxtraces, mmap2_headers) =
        iptr_perf_pt_reader::extract_pt_auxtraces_and_mmap_data(&buf)
            .context("Failed to parse perf.data format")?;

    let control_flow_handler = control_flow_handler::PerfAnalyzerControlFlowHandler::default();
    let memory_reader = PerfMmapBasedMemoryReader::new(&mmap2_headers);

    let edge_analyzer = EdgeAnalyzer::new(control_flow_handler, memory_reader);
    #[cfg(feature = "debug")]
    let mut packet_handler = iptr_decoder::packet_handler::combined::CombinedPacketHandler::new(
        iptr_decoder::packet_handler::log::PacketHandlerRawLogger::default(),
        edge_analyzer,
    );
    #[cfg(not(feature = "debug"))]
    let mut packet_handler = edge_analyzer;

    for pt_auxtrace in pt_auxtraces {
        iptr_decoder::decode(
            pt_auxtrace.auxtrace_data,
            DecodeOptions::default(),
            &mut packet_handler,
        )?;
    }

    Ok(())
}
