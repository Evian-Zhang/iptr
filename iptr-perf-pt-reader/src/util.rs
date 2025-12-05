#[inline(always)]
pub fn read_u16(data: &[u8], pos: usize) -> Option<u16> {
    let data = data.get(pos..)?;
    let chunk = data.first_chunk::<2>()?;
    Some(u16::from_ne_bytes(*chunk))
}

#[inline(always)]
pub fn read_u32(data: &[u8], pos: usize) -> Option<u32> {
    let data = data.get(pos..)?;
    let chunk = data.first_chunk::<4>()?;
    Some(u32::from_ne_bytes(*chunk))
}

#[inline(always)]
pub fn read_u64(data: &[u8], pos: usize) -> Option<u64> {
    let data = data.get(pos..)?;
    let chunk = data.first_chunk::<8>()?;
    Some(u64::from_ne_bytes(*chunk))
}
