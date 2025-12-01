use std::{borrow::Cow, io::Cursor};

use byteorder::LittleEndian;
use linux_perf_data::{
    PerfFileReader, PerfFileRecord, UserRecordType, linux_perf_event_reader::RecordType,
};

use crate::error::ReaderResult;

pub mod error;

pub fn extract_pt_aux_data(perf_data: &[u8]) -> ReaderResult<Vec<&[u8]>> {
    let mut pt_aux_datas = vec![];

    let PerfFileReader {
        mut perf_file,
        mut record_iter,
    } = PerfFileReader::parse_file(Cursor::new(perf_data))?;
    while let Some(record) = record_iter.next_record(&mut perf_file)? {
        let PerfFileRecord::UserRecord(record) = record else {
            continue;
        };
        if !matches!(record.record_type, UserRecordType::PERF_AUXTRACE) {
            continue;
        }

        let mut data = record.data;
        let size = data.read_u64::<LittleEndian>()?;
        let offset = data.read_u64::<LittleEndian>()?;
        let _reference = data.read_u64::<LittleEndian>()?;
        let idx = data.read_u32::<LittleEndian>()?;
        let _tid = data.read_u32::<LittleEndian>()?;
        let _cpu = data.read_u32::<LittleEndian>()?;
        let _reserved = data.read_u32::<LittleEndian>()?;

        println!(
            "misc {:x} size {size:x} offset {offset:x} _reference {_reference:x} idx {idx:x} next {:x}",
            record.misc,
            data.as_slice().len()
        );

        // let Some(aux_data) = perf_data.get()

        // pt_aux_datas.push(perf_data);
    }

    Ok(pt_aux_datas)
}
