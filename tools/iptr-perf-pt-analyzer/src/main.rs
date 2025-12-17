mod control_flow_handler;
mod memory_reader;

use anyhow::{Context, Result};
use clap::Parser;
use iptr_decoder::{
    DecodeOptions,
    packet_handler::{combined::CombinedPacketHandler, log::PacketHandlerRawLogger},
};
use iptr_edge_analyzer::EdgeAnalyzer;

use std::{fs::File, path::PathBuf};

/// Decode target intel PT packets in the low level and logs all details.
///
/// Set the environment variable `RUST_LOG=trace` for logging.
#[derive(Parser)]
struct Cmdline {
    /// Path of intel PT trace
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

    let mut control_flow_handler = control_flow_handler::PerfAnalyzerControlFlowHandler::default();
    let mut memory_reader = memory_reader::PerfMmapBasedMemoryReader::new(&mmap2_headers);

    let edge_analyzer = EdgeAnalyzer::new(&mut control_flow_handler, &mut memory_reader);
    let mut packet_handler =
        CombinedPacketHandler::new(PacketHandlerRawLogger::default(), edge_analyzer);

    for pt_auxtrace in pt_auxtraces {
        if let Err(err) = iptr_decoder::decode(
            pt_auxtrace.auxtrace_data,
            DecodeOptions::default(),
            &mut packet_handler,
        ) {
            log::error!("{err:?}");
        }
    }

    Ok(())
}
