use std::{fs::File, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
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

/// A standalone binary for libxdc-like evaluation
///
/// This program will decode the target Intel PT trace only once,
/// targeting at testing the performance of decoding.
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
    /// Path for writing bitmap output, if given.
    ///
    /// The bitmap is initialized with all zero data with
    /// 0x10000 size.
    #[arg(long)]
    bitmap_output: Option<PathBuf>,
}

fn main() -> Result<()> {
    env_logger::init();

    let Cmdline {
        input,
        page_dump,
        page_addr,
        range_start,
        range_end,
        bitmap_output,
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

    let file = File::open(input).context("Failed to open input file")?;
    // SAFETY: check the safety requirements of memmap2 documentation
    let buf = unsafe { memmap2::Mmap::map(&file).context("Failed to mmap input file")? };

    iptr_decoder::decode(&buf, DecodeOptions::default(), &mut packet_handler).unwrap();

    #[cfg(all(not(feature = "debug"), feature = "diagnose"))]
    iptr_libxdc_exp::report_diagnose(
        &packet_handler.diagnose(),
        &packet_handler.handler().diagnose(),
    );

    drop(packet_handler);
    if let Some(bitmap_output) = bitmap_output {
        std::fs::write(bitmap_output, &bitmap)?;
    }

    Ok(())
}
