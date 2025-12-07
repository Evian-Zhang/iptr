#![no_std]
extern crate alloc;

use alloc::vec::Vec;

pub mod error;
mod util;

use crate::error::{ReaderError, ReaderResult};

const PERF_RECORD_AUXTRACE: u32 = 71;

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
        let cur_pos = pos;
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
                pos = cur_pos.saturating_add(perf_event_header.size as usize);
            }
        }
    }

    Ok(pt_auxtraces)
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

#[allow(unused)]
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

pub struct PerfRecordAuxtrace<'a> {
    pub size: u64,
    pub offset: u64,
    pub reference: u64,
    pub idx: u32,
    pub tid: u32,
    pub cpu: u32,
    pub auxtrace_data: &'a [u8],
}

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
