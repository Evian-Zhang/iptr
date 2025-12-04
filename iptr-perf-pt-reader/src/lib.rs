use std::{
    borrow::Cow,
    io::{Cursor, Read},
};

use byteorder::LittleEndian;
use linux_perf_data::{
    PerfFileReader, PerfFileRecord, UserRecordType, linux_perf_event_reader::RecordType,
};

use crate::error::ReaderResult;

pub mod error;

const PERF_RECORD_AUXTRACE: u32 = 71;

pub fn extract_pt_aux_data(perf_data: &[u8]) -> ReaderResult<Vec<&[u8]>> {
    let mut pt_aux_datas = vec![];

    let mut cursor = Cursor::new(perf_data);
    let _ = PerfFileReader::parse_file(cursor.by_ref())?;
    let mut pos = cursor.position() as usize; // Skip Perf Header

    loop {
        let Some(perf_event_header) = read_header(perf_data, &mut pos) else {
            break;
        };
        match perf_event_header.r#type {
            PERF_RECORD_AUXTRACE => {}
            _ => {}
        }
    }

    Ok(pt_aux_datas)
}

struct PerfEventHeader {
    r#type: u32,
    misc: u16,
    size: u16,
}

fn read_header(perf_data: &[u8], pos: &mut usize) -> Option<PerfEventHeader> {
    let bytes = perf_data
        .get(*pos..)
        .and_then(|buf| buf.first_chunk::<4>())?;
    let r#type = u32::from_le_bytes(*bytes);
    *pos += 4;
    let bytes = perf_data
        .get(*pos..)
        .and_then(|buf| buf.first_chunk::<2>())?;
    let misc = u16::from_le_bytes(*bytes);
    *pos += 2;
    let bytes = perf_data
        .get(*pos..)
        .and_then(|buf| buf.first_chunk::<2>())?;
    let size = u16::from_le_bytes(*bytes);
    *pos += 2;

    Some(PerfEventHeader { r#type, misc, size })
}
