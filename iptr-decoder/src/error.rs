//! This module contains definition of errors made when decoding

use core as std; // workaround for `perfect_derive`

use perfect_derive::perfect_derive;
use thiserror::Error;

use crate::HandlePacket;

/// Error for the decoding
#[derive(Error)]
#[perfect_derive(Debug)]
#[non_exhaustive]
pub enum DecoderError<H: HandlePacket> {
    /// Packet handler error
    #[error("Packet handler error")]
    PacketHandler(#[source] H::Error),
    /// Invalid packet
    #[error("Invalid packet")]
    InvalidPacket,
    /// No PSB packet found
    ///
    /// The PSB packet is required to be the start position
    /// for decoding
    #[error("No PSB packet found")]
    NoPsb,
    /// Unexpected EOF
    #[error("Unexpected EOF")]
    UnexpectedEOF,
}

pub(crate) type DecoderResult<T, H> = core::result::Result<T, DecoderError<H>>;
