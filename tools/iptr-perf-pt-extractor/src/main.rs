use std::{ffi::OsStr, fs::File, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;

/// Extract Intel PT aux data from perf.data
///
/// Set the environment variable `RUST_LOG=trace` for logging.
#[derive(Parser)]
struct Cmdline {
    /// Path of perf.data
    #[arg(short, long)]
    input: PathBuf,
    /// Path for output.
    ///
    /// If no `--first-only` is specified, this path should refer to
    /// a directory, all PT traces inside the perf.data will be extracted
    /// into that directory; if `--first-only` is specified, this option
    /// is used for the file path for extracted PT trace.
    #[arg(short, long)]
    output: PathBuf,
    /// Only extract the first PT trace, ignoring all others.
    #[arg(long)]
    first_only: bool,
}

fn main() -> Result<()> {
    env_logger::init();

    let Cmdline {
        input,
        output,
        first_only,
    } = Cmdline::parse();

    let file = File::open(&input).context("Failed to open input file")?;
    // SAFETY: check the safety requirements of memmap2 documentation
    let buf = unsafe { memmap2::Mmap::map(&file).context("Failed to mmap input file")? };
    let origin_filename = input.file_name().unwrap_or_else(|| OsStr::new("perf.data"));

    let pt_auxtraces = iptr_perf_pt_reader::extract_pt_auxtraces(&buf)?;

    for pt_auxtrace in pt_auxtraces {
        if first_only {
            std::fs::write(&output, pt_auxtrace.auxtrace_data)
                .context("Failed to write auxtrace data")?;
            log::info!("Extracted {}", output.display());
            return Ok(());
        }
        let target_path = output.join(format!(
            "{}-aux-idx{}.bin",
            origin_filename.display(),
            pt_auxtrace.idx
        ));
        std::fs::write(&target_path, pt_auxtrace.auxtrace_data)
            .context("Failed to write auxtrace data")?;
        log::info!("Extracted {}", target_path.display());
    }

    Ok(())
}
