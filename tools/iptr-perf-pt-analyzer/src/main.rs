mod memory_reader;

use anyhow::{Context, Result};
use clap::Parser;

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

    let memory_reader = memory_reader::PerfMmapBasedMemoryReader::new(&mmap2_headers);

    Ok(())
}
