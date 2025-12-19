//! Handler for logging each packets
//!
//! The handler provided in this module is [`PacketHandlerRawLogger`], it logs every packet details.
//! This handler is extremely useful if you are debugging your own packet handler. You can use this
//! handler with [`CombinedPacketHandler`][super::combined::CombinedPacketHandler]:
//!
//! ```rust
//! # use iptr_decoder::packet_handler::{packet_counter::PacketCounter, combined::CombinedPacketHandler, log::PacketHandlerRawLogger};
//! # let custom_packet_handler = PacketCounter::default();
//! // let custom_packet_handler = ...
//! let handler1 = PacketHandlerRawLogger::default();
//! let handler2 = custom_packet_handler;
//! let handler = CombinedPacketHandler::new(handler1, handler2);
//! // Use handler1 ...
//! ```

use core::convert::Infallible;

use crate::{DecoderContext, HandlePacket, IpReconstructionPattern, PtwPayload};

/// Handler for logging each packets
#[derive(Default)]
pub struct PacketHandlerRawLogger {}

impl HandlePacket for PacketHandlerRawLogger {
    // This logger will never error
    type Error = Infallible;

    fn on_short_tnt_packet(
        &mut self,
        _context: &DecoderContext,
        packet_byte: u8,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        log::trace!(
            "[Short TNT packet]\tpacket byte: {packet_byte:#010b}\thighest bit: {highest_bit}"
        );
        Ok(())
    }

    fn on_long_tnt_packet(
        &mut self,
        _context: &DecoderContext,
        packet_bytes: u64,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        log::trace!(
            "[Long TNT packet]\tpacket bytes: {packet_bytes:#066b}\thighest bit: {highest_bit}"
        );
        Ok(())
    }

    fn on_tip_packet(
        &mut self,
        _context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        log::trace!("[TIP packet]\tip reconstruction: {ip_reconstruction_pattern}");
        Ok(())
    }

    fn on_tip_pgd_packet(
        &mut self,
        _context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        log::trace!("[TIP.PGD packet]\tip reconstruction: {ip_reconstruction_pattern}");
        Ok(())
    }

    fn on_tip_pge_packet(
        &mut self,
        _context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        log::trace!("[TIP.PGE packet]\tip reconstruction: {ip_reconstruction_pattern}");
        Ok(())
    }

    fn on_fup_packet(
        &mut self,
        _context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        log::trace!("[FUP packet]\tip reconstruction: {ip_reconstruction_pattern}");
        Ok(())
    }

    fn on_pad_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        log::trace!("[PAD packet]");
        Ok(())
    }

    fn on_cyc_packet(
        &mut self,
        _context: &DecoderContext,
        cyc_packet: &[u8],
    ) -> Result<(), Self::Error> {
        log::trace!(
            "[CYC packet]\t{}",
            cyc_packet
                .iter()
                .map(|byte| alloc::format!("{byte:#010b}"))
                .collect::<alloc::vec::Vec<_>>()
                .join(", ")
        );
        Ok(())
    }

    fn on_mode_packet(
        &mut self,
        _context: &DecoderContext,
        leaf_id: u8,
        mode: u8,
    ) -> Result<(), Self::Error> {
        log::trace!("[MODE packet]\tLeaf ID: {leaf_id:#010b}\tmode:{mode:#010b}");
        Ok(())
    }

    fn on_mtc_packet(
        &mut self,
        _context: &DecoderContext,
        ctc_payload: u8,
    ) -> Result<(), Self::Error> {
        log::trace!("[MTC packet]\tCTC: {ctc_payload:#010b}");
        Ok(())
    }

    fn on_tsc_packet(
        &mut self,
        _context: &DecoderContext,
        tsc_value: u64,
    ) -> Result<(), Self::Error> {
        log::trace!("[TSC packet]\tTSC: {tsc_value:#066b}");
        Ok(())
    }

    fn on_cbr_packet(
        &mut self,
        _context: &DecoderContext,
        core_bus_ratio: u8,
    ) -> Result<(), Self::Error> {
        log::trace!("[CBR packet]\tCore:Bus Ratio: {core_bus_ratio:#010b}");
        Ok(())
    }

    fn on_tma_packet(
        &mut self,
        _context: &DecoderContext,
        ctc: u16,
        fast_counter: u8,
        fc8: bool,
    ) -> Result<(), Self::Error> {
        log::trace!(
            "[TMA packet]\tCTC: {ctc:#018b}\tFast Counter: {fast_counter:#010b}\tFC8: {fc8}"
        );
        Ok(())
    }

    fn on_vmcs_packet(
        &mut self,
        _context: &DecoderContext,
        vmcs_pointer: u64,
    ) -> Result<(), Self::Error> {
        log::trace!("[VMCS packet]\tVMCS Pointer: {vmcs_pointer:#x}");
        Ok(())
    }

    fn on_ovf_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        log::trace!("[OVF packet]");
        Ok(())
    }

    fn on_psb_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        log::trace!("[PSB packet]");
        Ok(())
    }

    fn on_psbend_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        log::trace!("[PSBEND packet]");
        Ok(())
    }

    fn on_trace_stop_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        log::trace!("[TRACE STOP packet]");
        Ok(())
    }

    fn on_pip_packet(
        &mut self,
        _context: &DecoderContext,
        cr3: u64,
        rsvd_nr: bool,
    ) -> Result<(), Self::Error> {
        log::trace!("[PIP packet]\tCR3: {cr3:#x}\tRSVD.NR: {rsvd_nr}");
        Ok(())
    }

    fn on_mnt_packet(
        &mut self,
        _context: &DecoderContext,
        payload: u64,
    ) -> Result<(), Self::Error> {
        log::trace!("[MNT packet]\tPayload: {payload:#x}");
        Ok(())
    }

    fn on_ptw_packet(
        &mut self,
        _context: &DecoderContext,
        ip_bit: bool,
        payload: PtwPayload,
    ) -> Result<(), Self::Error> {
        log::trace!("[PTW packet]\tIP bit: {ip_bit}\tPayload: {payload}");
        Ok(())
    }

    fn on_exstop_packet(
        &mut self,
        _context: &DecoderContext,
        ip_bit: bool,
    ) -> Result<(), Self::Error> {
        log::trace!("[EXSTOP packet]\tIP bit: {ip_bit}");
        Ok(())
    }

    fn on_mwait_packet(
        &mut self,
        _context: &DecoderContext,
        mwait_hints: u8,
        ext: u8,
    ) -> Result<(), Self::Error> {
        log::trace!("[MWAIT packet]\tMWAIT hints: {mwait_hints:#010b}\tEXT: {ext:#010b}");
        Ok(())
    }

    fn on_pwre_packet(
        &mut self,
        _context: &DecoderContext,
        hw: bool,
        resolved_thread_c_state: u8,
        resolved_thread_sub_c_state: u8,
    ) -> Result<(), Self::Error> {
        log::trace!(
            "[PWRE packet]\tHW: {hw}\tResolved Thread C-State: {resolved_thread_c_state:#010b}\tResolved Thread Sub C-State: {resolved_thread_sub_c_state:#010b}"
        );
        Ok(())
    }

    fn on_pwrx_packet(
        &mut self,
        _context: &DecoderContext,
        last_core_c_state: u8,
        deepest_core_c_state: u8,
        wake_reason: u8,
    ) -> Result<(), Self::Error> {
        log::trace!(
            "[PWRX packet]\tLast Core C-State: {last_core_c_state:#010b}\tDeepest Core C-State: {deepest_core_c_state:#010b}\tWake Reason: {wake_reason:#010b}"
        );
        Ok(())
    }

    fn on_evd_packet(
        &mut self,
        _context: &DecoderContext,
        r#type: u8,
        payload: u64,
    ) -> Result<(), Self::Error> {
        log::trace!("[EVD packet]\tType: {type:#010b}\tPayload: {payload:#x}");
        Ok(())
    }

    fn on_cfe_packet(
        &mut self,
        _context: &DecoderContext,
        ip_bit: bool,
        r#type: u8,
        vector: u8,
    ) -> Result<(), Self::Error> {
        log::trace!("[CFE packet]\tIP bit: {ip_bit}\tType: {type:#010b}\tVector: {vector:#010b}");
        Ok(())
    }
}
