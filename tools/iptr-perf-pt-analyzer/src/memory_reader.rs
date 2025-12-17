use std::{fs::File, path::Path};

use iptr_perf_pt_reader::PerfMmap2Header;
use memmap2::{Mmap, MmapOptions};

pub struct PerfMmapBasedMemoryReader {
    entries: Vec<MmapedEntry>,
}

struct MmapedEntry {
    mmap: Mmap,
    virtual_address: u64,
}

pub enum PerfMmapBasedMemoryReaderError {}

type Result<T> = std::result::Result<T, PerfMmapBasedMemoryReaderError>;

impl PerfMmapBasedMemoryReader {
    pub fn new(mmap2_headers: &[PerfMmap2Header]) -> Self {
        let mut entries = Vec::with_capacity(mmap2_headers.len());

        for mmap2_header in mmap2_headers {
            let filename_path = Path::new(&mmap2_header.filename);
            if !filename_path.is_absolute() {
                log::warn!(
                    "Mmaped filename {} is not absolute path, skip.",
                    mmap2_header.filename
                );
                continue;
            }
            let Ok(file) = File::open(filename_path).inspect_err(|err| {
                log::error!(
                    "Failed to open mmaped file {}: {err:?}",
                    mmap2_header.filename
                );
            }) else {
                continue;
            };
            // SAFETY: check the safety requirements of memmap2 documentation
            let mmap_res = unsafe {
                MmapOptions::default()
                    .len(mmap2_header.len as usize)
                    .offset(mmap2_header.pgoff)
                    .map(&file)
            };
            let Ok(mmap) = mmap_res.inspect_err(|err| {
                log::error!("Failed to mmap file {}: {err:?}", mmap2_header.filename);
            }) else {
                continue;
            };
            if mmap.len() != mmap2_header.len as usize {
                log::error!("Mismatched mmap length for {}.", mmap2_header.filename);
                continue;
            }
            log::trace!(
                "Mmaped {:016x}--{:016x}\t{}",
                mmap2_header.addr,
                mmap2_header.addr + mmap2_header.len,
                mmap2_header.filename
            );
            entries.push(MmapedEntry {
                mmap,
                virtual_address: mmap2_header.addr,
            });
        }

        entries.sort_by_key(|entry| entry.virtual_address);

        Self { entries }
    }
}
