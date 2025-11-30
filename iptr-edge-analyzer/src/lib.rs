mod control_flow_analyzer;
mod control_flow_handler;
mod error;
mod memory_reader;
mod tnt_buffer;

use iptr_decoder::{DecoderContext, HandlePacket, IpReconstructionPattern};

use crate::{
    control_flow_analyzer::ControlFlowAnalyzer, error::AnalyzerError, tnt_buffer::TntBuffer,
};
pub use crate::{control_flow_handler::HandleControlFlow, memory_reader::ReadMemory};

pub struct EdgeAnalyzer<'a, H: HandleControlFlow, R: ReadMemory> {
    /// IP-reconstruction-specific field.
    ///
    /// This is not always be the last IP in the packet. It has
    /// special semantic according to Intel. Do not use thie field
    /// until you know what you are doing.
    last_ip: u64,
    tnt_buffer: TntBuffer,
    control_flow_analyzer: ControlFlowAnalyzer,
    handler: &'a mut H,
    reader: &'a mut R,
}

impl<'a, H: HandleControlFlow, R: ReadMemory> EdgeAnalyzer<'a, H, R> {
    pub fn new(handler: &'a mut H, reader: &'a mut R) -> Self {
        Self {
            last_ip: 0,
            tnt_buffer: TntBuffer::new(),
            control_flow_analyzer: ControlFlowAnalyzer::new(),
            handler,
            reader,
        }
    }

    fn reconstruct_ip_and_update_last(
        &mut self,
        ip_reconstruction: IpReconstructionPattern,
    ) -> Option<u64> {
        use IpReconstructionPattern::*;
        let ip = match ip_reconstruction {
            OutOfContext => {
                // `last_ip` is not updated
                return None;
            }
            TwoBytesWithLastIp(payload) => (self.last_ip & 0xFFFFFFFFFFFF0000) | (payload as u64),
            FourBytesWithLastIp(payload) => (self.last_ip & 0xFFFFFFFF00000000) | (payload as u64),
            SixBytesExtended(payload) => (((payload << 16) as i64) >> 16) as u64,
            SixBytesWithLastIp(payload) => (self.last_ip & 0xFFFF000000000000) | (payload as u64),
            EightBytes(payload) => payload,
        };
        self.last_ip = ip;

        Some(ip)
    }
}

impl<'a, H, R> HandlePacket for EdgeAnalyzer<'a, H, R>
where
    H: HandleControlFlow,
    AnalyzerError<H, R>: std::error::Error,
    R: ReadMemory,
{
    type Error = AnalyzerError<H, R>;

    fn on_short_tnt_packet(
        &mut self,
        context: &DecoderContext,
        packet_byte: u8,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        self.control_flow_analyzer.on_short_tnt_packet(
            self.handler,
            self.reader,
            packet_byte,
            highest_bit,
        )?;

        Ok(())
    }
}
