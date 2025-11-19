use thiserror::Error;

use crate::HandlePacket;

#[derive(Error, Debug)]
pub enum DecoderError<H: HandlePacket> {
    /// Packet handler error
    #[error("Packet handler error")]
    PacketHandler(#[source] H::Error),
    /// Invalid packet
    #[error("Invalid packet")]
    InvalidPacket,
    /// Unexpected EOF
    #[error("Unexpected EOF")]
    UnexpectedEOF,
    /// Currently unimplemented
    #[error("Unimplemented")]
    Unimplemented,
    /// Unexpected decoder error
    #[error("Unexpected decoder error")]
    Unexpected,
}

pub(crate) type DecoderResult<T, H> = std::result::Result<T, DecoderError<H>>;
