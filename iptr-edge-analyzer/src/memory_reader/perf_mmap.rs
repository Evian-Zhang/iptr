//! This module contains a memory reader that re-construct memory content
//! from `perf.data` files.

use std::{
    fs::File,
    path::{Path, PathBuf},
};

use super::ReadMemory;
use iptr_perf_pt_reader::PerfMmap2Header;
use memmap2::{Mmap, MmapOptions};
use thiserror::Error;

/// Memory reader that re-construct memory content from `perf.data` files.
///
/// To create a memory reader from perf.data, you should make sure
/// that all binary images involved in the process that be recorded
/// into perf.data are not modified and still in their original paths
/// (perf.data only records the mmap operation for the target process,
/// we use the arguments of mmap to reconstruct the target memory)
///
/// You should not use this struct if your `perf.data` also records kernel
/// traces, since the kernel memory information would not be recorded in
/// the `perf.data` file.
pub struct PerfMmapBasedMemoryReader {
    /// Recorded mmapped contents
    entries: Vec<MmappedEntry>,
}

/// Information of mmapped entries.
///
/// This struct can be retrieved by [`PerfMmapBasedMemoryReader::mmapped_entries`]
pub struct MmappedEntry {
    mmap: Mmap,
    virtual_address: u64,
}

impl MmappedEntry {
    /// Get the content of mmapped entry
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.mmap
    }

    /// Get the virtual address of mmapped entry when
    /// Intel PT trace is recorded
    #[must_use]
    pub fn virtual_address(&self) -> u64 {
        self.virtual_address
    }
}

/// Error type for [`PerfMmapBasedMemoryReader`] in the
/// implementation of [`ReadMemory`]
#[derive(Debug, Error)]
pub enum PerfMmapBasedMemoryReaderError {
    /// The queried address is not mmapped
    #[error("Not mmapped area {0:#x} accessed")]
    NotMmapped(u64),
}

/// Error type for [`PerfMmapBasedMemoryReader`], only used in
/// [`PerfMmapBasedMemoryReader::new`].
#[derive(Debug, Error)]
pub enum PerfMmapBasedMemoryReaderCreateError {
    /// Failed to open mmapped file
    #[error("Failed to open mmapped file {}: {source}", path.display())]
    FileIo {
        /// Path of target file
        path: PathBuf,
        /// Source of error
        #[source]
        source: std::io::Error,
    },
    /// The mmapped file is not long enough to match the length
    /// recorded in the `perf.data`.
    #[error("Target file {} is shorter than mapped moment: expected {expect_length} bytes, but got {real_length} bytes.", path.display())]
    FileTooShort {
        /// Path of target file
        path: PathBuf,
        /// Length recorded in `perf.data`
        expect_length: u64,
        /// Real length of target file
        real_length: u64,
    },
}

impl PerfMmapBasedMemoryReader {
    /// Create a memory reader from mmap2 headers in perf.data.
    ///
    /// Some special mmapped regions (e.g. VDSO pages) will be skipped
    /// since we cannot get its content.
    #[expect(clippy::cast_possible_truncation)]
    pub fn new(
        mmap2_headers: &[PerfMmap2Header],
    ) -> Result<Self, PerfMmapBasedMemoryReaderCreateError> {
        let mut entries = Vec::with_capacity(mmap2_headers.len());

        for mmap2_header in mmap2_headers {
            let filename_path = Path::new(&mmap2_header.filename);
            if !filename_path.is_absolute() {
                // For example, VDSO
                log::warn!(
                    "Mmapped filename {} is not absolute path, skip.",
                    mmap2_header.filename
                );
                continue;
            }
            let file = File::open(filename_path).map_err(|io_err| {
                PerfMmapBasedMemoryReaderCreateError::FileIo {
                    path: filename_path.to_path_buf(),
                    source: io_err,
                }
            })?;
            // SAFETY: check the safety requirements of memmap2 documentation
            let mmap_res = unsafe {
                MmapOptions::default()
                    .len(mmap2_header.len as usize)
                    .offset(mmap2_header.pgoff)
                    .map(&file)
            };
            let mmap = mmap_res.map_err(|io_err| PerfMmapBasedMemoryReaderCreateError::FileIo {
                path: filename_path.to_path_buf(),
                source: io_err,
            })?;
            if mmap.len() as u64 != mmap2_header.len {
                return Err(PerfMmapBasedMemoryReaderCreateError::FileTooShort {
                    path: filename_path.to_path_buf(),
                    expect_length: mmap2_header.len,
                    real_length: mmap.len() as u64,
                });
            }
            log::trace!(
                "Mmapped {:016x}--{:016x}\t{}",
                mmap2_header.addr,
                mmap2_header.addr.saturating_add(mmap2_header.len),
                mmap2_header.filename
            );
            entries.push(MmappedEntry {
                mmap,
                virtual_address: mmap2_header.addr,
            });
        }

        // Sort entries so that we can binary search it
        entries.sort_by_key(|entry| entry.virtual_address);

        Ok(Self { entries })
    }

    /// Get mmapped entries.
    ///
    /// The entries are guaranteed to be sorted by virtual addresses
    #[must_use]
    pub fn mmapped_entries(&self) -> &[MmappedEntry] {
        &self.entries
    }
}

impl ReadMemory for PerfMmapBasedMemoryReader {
    type Error = PerfMmapBasedMemoryReaderError;

    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    #[expect(clippy::cast_possible_truncation)]
    fn read_memory<T>(
        &mut self,
        address: u64,
        size: usize,
        callback: impl FnOnce(&[u8]) -> T,
    ) -> std::result::Result<T, Self::Error> {
        let pos = match self
            .entries
            .binary_search_by_key(&address, |entry| entry.virtual_address)
        {
            Ok(pos) => pos,
            Err(pos) => {
                if pos == 0 {
                    return Err(PerfMmapBasedMemoryReaderError::NotMmapped(address));
                }
                pos - 1
            }
        };
        // SAFETY: pos is generated by binary search, no possibility to out of bounds
        debug_assert!(pos < self.entries.len(), "Unexpected pos out of bounds!");
        let entry = unsafe { self.entries.get_unchecked(pos) };
        let start_offset = address - entry.virtual_address;
        let read_size = std::cmp::min(size, entry.mmap.len().saturating_sub(start_offset as usize));
        if read_size == 0 {
            return Err(PerfMmapBasedMemoryReaderError::NotMmapped(address));
        }
        let Some(mem) = entry
            .mmap
            .get((start_offset as usize)..((start_offset as usize).saturating_add(read_size)))
        else {
            return Err(PerfMmapBasedMemoryReaderError::NotMmapped(
                address.saturating_add(read_size as u64) - 1,
            ));
        };
        Ok(callback(mem))
    }
}
