//! Handler for counting total packets

use crate::{DecoderContext, HandlePacket, IpReconstructionPattern};

/// A [`HandlePacket`] instance for counting Intel PT packets
#[derive(Default)]
pub struct PacketCounter {
    packet_count: usize,
}

impl PacketCounter {
    /// Create a new [`PacketCounter`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the total packet count
    #[must_use]
    pub fn packet_count(&self) -> usize {
        self.packet_count
    }
}

impl HandlePacket for PacketCounter {
    // Will never fail
    type Error = core::convert::Infallible;

    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        self.packet_count = 0;
        Ok(())
    }

    fn on_short_tnt_packet(
        &mut self,
        _context: &DecoderContext,
        _packet_byte: u8,
        _highest_bit: u32,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_long_tnt_packet(
        &mut self,
        _context: &DecoderContext,
        _packet_bytes: u64,
        _highest_bit: u32,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_tip_packet(
        &mut self,
        _context: &DecoderContext,
        _ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_tip_pgd_packet(
        &mut self,
        _context: &DecoderContext,
        _ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_tip_pge_packet(
        &mut self,
        _context: &DecoderContext,
        _ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_fup_packet(
        &mut self,
        _context: &DecoderContext,
        _ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_pad_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_cyc_packet(
        &mut self,
        _context: &DecoderContext,
        _cyc_packet: &[u8],
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_mode_packet(
        &mut self,
        _context: &DecoderContext,
        _leaf_id: u8,
        _mode: u8,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_mtc_packet(
        &mut self,
        _context: &DecoderContext,
        _ctc_payload: u8,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_tsc_packet(
        &mut self,
        _context: &DecoderContext,
        _tsc_value: u64,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_cbr_packet(
        &mut self,
        _context: &DecoderContext,
        _core_bus_ratio: u8,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_tma_packet(
        &mut self,
        _context: &DecoderContext,
        _ctc: u16,
        _fast_counter: u8,
        _fc8: bool,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_vmcs_packet(
        &mut self,
        _context: &DecoderContext,
        _vmcs_pointer: u64,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_ovf_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_psb_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_psbend_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_trace_stop_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_pip_packet(
        &mut self,
        _context: &DecoderContext,
        _cr3: u64,
        _rsvd_nr: bool,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_mnt_packet(
        &mut self,
        _context: &DecoderContext,
        _payload: u64,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_ptw_packet(
        &mut self,
        _context: &DecoderContext,
        _ip_bit: bool,
        _payload: crate::PtwPayload,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_exstop_packet(
        &mut self,
        _context: &DecoderContext,
        _ip_bit: bool,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_mwait_packet(
        &mut self,
        _context: &DecoderContext,
        _mwait_hints: u8,
        _ext: u8,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_pwre_packet(
        &mut self,
        _context: &DecoderContext,
        _hw: bool,
        _resolved_thread_c_state: u8,
        _resolved_thread_sub_c_state: u8,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_pwrx_packet(
        &mut self,
        _context: &DecoderContext,
        _last_core_c_state: u8,
        _deepest_core_c_state: u8,
        _wake_reason: u8,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_evd_packet(
        &mut self,
        _context: &DecoderContext,
        _type: u8,
        _payload: u64,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }

    fn on_cfe_packet(
        &mut self,
        _context: &DecoderContext,
        _ip_bit: bool,
        _type: u8,
        _vector: u8,
    ) -> Result<(), Self::Error> {
        self.packet_count += 1;

        Ok(())
    }
}
