pub mod error;
mod raw_packet_handler;

use error::DecoderResult;

pub trait HandlePacket {
    /// Custom error type
    type Error: std::error::Error;

    /// Handle short TNT packet
    ///
    /// `packet_byte` is the whole byte of short TNT packet. `highest_bit`
    /// is the index of highest bit that represents a valid Taken/Not-taken bit.
    fn on_short_tnt_packet(&mut self, packet_byte: u8, highest_bit: u32)
    -> Result<(), Self::Error>;

    /// Handle PAD packet
    fn on_pad_packet(&mut self) -> Result<(), Self::Error>;

    /// Handle CYC packet
    ///
    /// `cyc_packet` is the total content of the CYC packet
    fn on_cyc_packet(&mut self, cyc_packet: &[u8]) -> Result<(), Self::Error>;

    /// Handle MODE packet
    ///
    /// `leaf_id` and `mode` is the leaf ID and mode of MODE packet.
    fn on_mode_packet(&mut self, leaf_id: u8, mode: u8) -> Result<(), Self::Error>;

    /// Handle MTC packet
    ///
    /// `ctc_payload` is the 8-bit CTC payload value
    fn on_mtc_packet(&mut self, ctc_payload: u8) -> Result<(), Self::Error>;

    /// Handle TSC packet
    ///
    /// `tsc_value` is the lower 7 bytes of current TSC value
    fn on_tsc_packet(&mut self, tsc_value: u64) -> Result<(), Self::Error>;
}

pub fn decode<H: HandlePacket>(buf: &[u8], packet_handler: &mut H) -> DecoderResult<(), H> {
    let mut pos = 0;

    raw_packet_handler::level1::decode(buf, &mut pos, packet_handler)
}
