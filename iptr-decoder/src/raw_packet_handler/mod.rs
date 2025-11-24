use core::marker::PhantomData;

use crate::{DecoderContext, HandlePacket, error::DecoderResult};

pub mod level1;
pub mod level2;

type RawPacketHandler<H> = fn(
    buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H>;

pub struct RawPacketHandlers<H: HandlePacket> {
    phantom: PhantomData<H>,
}
