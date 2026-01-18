use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::Parser;
use iptr_edge_analyzer::memory_reader::perf_mmap::PerfMmapBasedMemoryReader;

/// Create libxdc-experiments-compatible memory dump.
///
/// Set the environment variable `RUST_LOG=trace` for logging.
#[derive(Parser)]
struct Cmdline {
    /// Path of intel PT trace in perf.data format
    #[arg(short, long)]
    input: PathBuf,
    /// Path for generated page dump
    #[arg(long)]
    page_dump: PathBuf,
    /// Path for generated page address
    #[arg(long)]
    page_addr: PathBuf,
}

const PAGE_SIZE: usize = 0x1000;

fn main() -> Result<()> {
    env_logger::init();

    let Cmdline {
        input,
        page_dump,
        page_addr,
    } = Cmdline::parse();
    let file = File::open(input).context("Failed to open input file")?;
    // SAFETY: check the safety requirements of memmap2 documentation
    let buf = unsafe { memmap2::Mmap::map(&file).context("Failed to mmap input file")? };

    let (_pt_auxtraces, mmap2_headers) =
        iptr_perf_pt_reader::extract_pt_auxtraces_and_mmap_data(&buf)
            .context("Failed to parse perf.data format")?;
    let memory_reader = PerfMmapBasedMemoryReader::new(&mmap2_headers)?;
    let mut page_dump_file =
        BufWriter::new(File::create(page_dump).context("Failed to create page dump file")?);
    let mut page_addr_file =
        BufWriter::new(File::create(page_addr).context("Failed to create page addr file")?);

    let mut page_buf = [0u8; PAGE_SIZE];
    for mmaped_entry in memory_reader.mmapped_entries() {
        log::info!(
            "Writing mmaped entry at {:#x} with size {:#x}",
            mmaped_entry.virtual_address(),
            mmaped_entry.content().len()
        );
        let content = mmaped_entry.content();
        let complete_page_count = content.len() / PAGE_SIZE;
        let complete_page_size = PAGE_SIZE * complete_page_count;
        let complete_page = content.get(0..complete_page_size).expect("Unexpected!");
        page_dump_file
            .write_all(complete_page)
            .context("Failed to write to page dump file")?;

        for page_count in 0..complete_page_count {
            let page_addr = mmaped_entry.virtual_address() + (page_count * PAGE_SIZE) as u64;
            page_addr_file
                .write_all(&page_addr.to_le_bytes())
                .context("Failed to write to page addr file")?;
        }

        if complete_page_size != content.len() {
            let remain_page_size = content.len() - complete_page_size;
            let remain_page = content.get(complete_page_size..).expect("Unexpected!");
            assert!(
                remain_page_size < PAGE_SIZE,
                "Unexpected! Remain page size too large!"
            );
            page_buf.fill(0);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    remain_page.as_ptr(),
                    page_buf.as_mut_ptr(),
                    remain_page_size,
                );
            }
            page_dump_file
                .write_all(&page_buf)
                .context("Failed to write to page dump file")?;

            let page_addr =
                mmaped_entry.virtual_address() + (complete_page_count * PAGE_SIZE) as u64;
            page_addr_file
                .write_all(&page_addr.to_le_bytes())
                .context("Failed to write to page addr file")?;
        }
    }

    Ok(())
}
