use std::{ffi::OsStr, fs::File, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;

/// Extract Intel PT aux data from perf.data
#[derive(Parser)]
struct Cmdline {
    /// Path of perf.data
    #[arg(short, long)]
    input: PathBuf,
    /// Output directory
    #[arg(short, long)]
    output_dir: PathBuf,
}

fn main() -> Result<()> {
    let Cmdline { input, output_dir } = Cmdline::parse();

    let file = File::open(&input).context("Failed to open input file")?;
    // SAFETY: check the safety requirements of memmap2 documentation
    let buf = unsafe { memmap2::Mmap::map(&file).context("Failed to mmap input file")? };
    let origin_filename = input
        .file_name()
        .unwrap_or_else(|| &OsStr::new("perf.data"));

    let mut index = 0;
    iptr_perf_pt_reader::extract_pt_aux_data(&buf)?;

    // let target_path = output_dir.join(format!("{}-aux-idx{index}.bin", origin_filename.display()));
    // index += 1;
    // std::fs::write(target_path, aux_data).context("Failed to write")

    Ok(())
}
