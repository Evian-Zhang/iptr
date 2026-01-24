#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs)]

extern crate alloc;

use core::ffi::CStr;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

mod error;
mod util;

pub use crate::error::ReaderError;
use crate::error::ReaderResult;

/// Value of `type`` field for mmapped perf header
const PERF_RECORD_MMAP2: u32 = 10;
/// Value of `type` field for auxtrace header
const PERF_RECORD_AUXTRACE: u32 = 71;

/// Extract raw Intel PT traces from `perf.data`.
#[expect(clippy::cast_possible_truncation)]
pub fn extract_pt_auxtraces(perf_data: &[u8]) -> ReaderResult<Vec<PerfRecordAuxtrace<'_>>> {
    let mut pt_auxtraces = Vec::new();

    let (pos, total_size) = read_perf_header(perf_data)?;
    let mut pos = pos as usize;
    let end_pos = pos.saturating_add(total_size as usize);
    let Some(perf_data) = perf_data.get(0..end_pos) else {
        return Err(ReaderError::UnexpectedEOF);
    };

    loop {
        if pos >= end_pos {
            break;
        }
        let perf_header_start_pos = pos;
        let Some(perf_event_header) = read_perf_event_header(perf_data, &mut pos) else {
            return Err(ReaderError::UnexpectedEOF);
        };
        if perf_event_header.size == 0 {
            // This will lead to infinite loop
            return Err(ReaderError::InvalidPerfData);
        }
        match perf_event_header.r#type {
            PERF_RECORD_AUXTRACE => {
                let Some(auxtrace) = read_auxtrace(perf_data, &mut pos) else {
                    return Err(ReaderError::UnexpectedEOF);
                };
                pt_auxtraces.push(auxtrace);
            }
            _ => {
                pos = perf_header_start_pos.saturating_add(perf_event_header.size as usize);
            }
        }
    }

    Ok(pt_auxtraces)
}

/// Extract raw Intel PT traces alongwith mmapped information from `perf.data`.
#[expect(clippy::cast_possible_truncation)]
pub fn extract_pt_auxtraces_and_mmap_data(
    perf_data: &[u8],
) -> ReaderResult<(Vec<PerfRecordAuxtrace<'_>>, Vec<PerfMmap2Header>)> {
    let mut pt_auxtraces = Vec::new();
    let mut mmap2_headers = Vec::new();

    let (pos, total_size) = read_perf_header(perf_data)?;
    let mut pos = pos as usize;
    let end_pos = pos.saturating_add(total_size as usize);
    let Some(perf_data) = perf_data.get(0..end_pos) else {
        return Err(ReaderError::UnexpectedEOF);
    };

    loop {
        if pos >= end_pos {
            break;
        }
        let perf_header_start_pos = pos;
        let Some(perf_event_header) = read_perf_event_header(perf_data, &mut pos) else {
            return Err(ReaderError::UnexpectedEOF);
        };
        if perf_event_header.size == 0 {
            // This will lead to infinite loop
            return Err(ReaderError::InvalidPerfData);
        }
        match perf_event_header.r#type {
            PERF_RECORD_AUXTRACE => {
                let Some(auxtrace) = read_auxtrace(perf_data, &mut pos) else {
                    return Err(ReaderError::UnexpectedEOF);
                };
                pt_auxtraces.push(auxtrace);
            }
            PERF_RECORD_MMAP2 => {
                let end_pos = perf_header_start_pos.saturating_add(perf_event_header.size as usize);
                let Some(mmap2_header) = read_mmap2(perf_data, pos, end_pos) else {
                    return Err(ReaderError::InvalidPerfData);
                };
                mmap2_headers.push(mmap2_header);
                pos = end_pos;
            }
            _ => {
                pos = perf_header_start_pos.saturating_add(perf_event_header.size as usize);
            }
        }
    }

    Ok((pt_auxtraces, mmap2_headers))
}

fn read_perf_header(perf_data: &[u8]) -> ReaderResult<(u64, u64)> {
    let mut pos = 0;
    let magic = util::read_u64(perf_data, pos).ok_or(ReaderError::UnexpectedEOF)?;
    pos += 8;
    if magic.to_le_bytes().as_slice() != b"PERFILE2" {
        return Err(ReaderError::InvalidPerfData);
    }

    let _size = util::read_u64(perf_data, pos).ok_or(ReaderError::UnexpectedEOF)?;
    pos += 8;

    let _attr_size = util::read_u64(perf_data, pos).ok_or(ReaderError::UnexpectedEOF)?;
    pos += 8;

    let _attrs_section =
        read_perf_file_section(perf_data, &mut pos).ok_or(ReaderError::UnexpectedEOF)?;
    let data_section =
        read_perf_file_section(perf_data, &mut pos).ok_or(ReaderError::UnexpectedEOF)?;

    let (offset, size) = data_section;
    Ok((offset, size))
}

fn read_perf_file_section(perf_data: &[u8], pos: &mut usize) -> Option<(u64, u64)> {
    let offset = util::read_u64(perf_data, *pos)?;
    *pos += 8;
    let size = util::read_u64(perf_data, *pos)?;
    *pos += 8;

    Some((offset, size))
}

#[expect(unused)]
struct PerfEventHeader {
    r#type: u32,
    misc: u16,
    size: u16,
}

fn read_perf_event_header(perf_data: &[u8], pos: &mut usize) -> Option<PerfEventHeader> {
    let r#type = util::read_u32(perf_data, *pos)?;
    *pos += 4;
    let misc = util::read_u16(perf_data, *pos)?;
    *pos += 2;
    let size = util::read_u16(perf_data, *pos)?;
    *pos += 2;

    Some(PerfEventHeader { r#type, misc, size })
}

/// AUXTRACE in `perf.data`
pub struct PerfRecordAuxtrace<'a> {
    /// Size of [`auxtrace_data`][Self::auxtrace_data]
    pub size: u64,
    /// Offset
    pub offset: u64,
    /// Referemce
    pub reference: u64,
    /// Index of auxtrace in perf.data
    pub idx: u32,
    /// Thread id
    pub tid: u32,
    /// CPU id
    pub cpu: u32,
    /// Real Intel PT data
    pub auxtrace_data: &'a [u8],
}

#[expect(clippy::cast_possible_truncation)]
fn read_auxtrace<'a>(perf_data: &'a [u8], pos: &mut usize) -> Option<PerfRecordAuxtrace<'a>> {
    let size = util::read_u64(perf_data, *pos)?;
    *pos += 8;
    let offset = util::read_u64(perf_data, *pos)?;
    *pos += 8;
    let reference = util::read_u64(perf_data, *pos)?;
    *pos += 8;
    let idx = util::read_u32(perf_data, *pos)?;
    *pos += 4;
    let tid = util::read_u32(perf_data, *pos)?;
    *pos += 4;
    let cpu = util::read_u32(perf_data, *pos)?;
    *pos += 4;
    let _reserved = util::read_u32(perf_data, *pos)?;
    *pos += 4;

    if size == 0 {
        return None;
    }
    let auxtrace_data = perf_data.get(*pos..(pos.saturating_add(size as usize)))?;
    *pos = pos.saturating_add(size as usize);

    Some(PerfRecordAuxtrace {
        size,
        offset,
        reference,
        idx,
        tid,
        cpu,
        auxtrace_data,
    })
}

/// Mmap2 header in `perf.data`
pub struct PerfMmap2Header {
    /// Process id
    pub pid: u32,
    /// Thread id
    pub tid: u32,
    /// Target address
    pub addr: u64,
    /// Mmapped length
    pub len: u64,
    /// Offset of file
    pub pgoff: u64,
    /// inode information
    pub inode: [u8; 24],
    /// Permissions
    pub prot: u32,
    /// Mmapped flags
    pub flags: u32,
    /// Mmapped filename
    pub filename: String,
}

fn read_mmap2(perf_data: &[u8], start_pos: usize, end_pos: usize) -> Option<PerfMmap2Header> {
    let mut pos = start_pos;
    let pid = util::read_u32(perf_data, pos)?;
    pos += 4;
    let tid = util::read_u32(perf_data, pos)?;
    pos += 4;
    let addr = util::read_u64(perf_data, pos)?;
    pos += 8;
    let len = util::read_u64(perf_data, pos)?;
    pos += 8;
    let pgoff = util::read_u64(perf_data, pos)?;
    pos += 8;
    let inode = *perf_data
        .get(pos..)
        .and_then(|buf| buf.first_chunk::<24>())?;
    pos += 24;
    let prot = util::read_u32(perf_data, pos)?;
    pos += 4;
    let flags = util::read_u32(perf_data, pos)?;
    pos += 4;
    if pos >= end_pos {
        return None;
    }
    let filename_buf = perf_data.get(pos..end_pos)?;
    let filename_c_str = CStr::from_bytes_until_nul(filename_buf).ok()?;
    let filename_str = filename_c_str.to_str().ok()?;
    let filename = filename_str.to_string();

    Some(PerfMmap2Header {
        pid,
        tid,
        addr,
        len,
        pgoff,
        inode,
        prot,
        flags,
        filename,
    })
}
