use std::marker::PhantomData;

use crate::{HandlePacket, error::DecoderResult};

pub mod level1;
pub mod level2;

type RawPacketHandler<H> =
    fn(buf: &[u8], pos: &mut usize, byte: u8, packet_handler: &mut H) -> DecoderResult<(), H>;

pub struct RawPacketHandlers<H: HandlePacket> {
    phantom: PhantomData<H>,
}
