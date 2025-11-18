use thiserror::Error;

use crate::HandlePacket;

#[derive(Error, Debug)]
pub enum DecoderError<H: HandlePacket> {
    #[error("Packet handler error")]
    PacketHandler(#[source] H::Error),
    #[error("Invalid packet")]
    InvalidPacket,
    #[error("Unexpected EOF")]
    UnexpectedEOF,
    #[error("Unexpected decoder error")]
    Unexpected,
}

pub(crate) type DecoderResult<T, H> = std::result::Result<T, DecoderError<H>>;
