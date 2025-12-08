#![no_std]

pub mod error;
mod raw_packet_handler;

pub use raw_packet_handler::{level1::IpReconstructionPattern, level2::PtwPayload};

use crate::error::{DecoderError, DecoderResult};

/// Packet handler trait
///
/// The default implementations of all packet handlers
/// are nops.
pub trait HandlePacket {
    /// Custom error type
    type Error: core::error::Error;

    /// Handle short TNT packet
    ///
    /// `packet_byte` is the whole byte of short TNT packet. `highest_bit`
    /// is the index of highest bit that represents a valid Taken/Not-taken bit,
    /// guaranteed to be in range 0..=6
    ///
    /// If `highest_bit` is 0, this means there is no Taken/Not-taken bits.
    #[allow(unused)]
    fn on_short_tnt_packet(
        &mut self,
        context: &DecoderContext,
        packet_byte: u8,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle short TNT packet
    ///
    /// `packet_bytes` is the whole 6 bytes of long TNT packet payload. The
    /// upper 2 bytes are guaranteed to be cleared.
    /// `highest_bit` is the index of highest bit that represents a valid
    /// Taken/Not-taken bit, guaranteed to be in range 0..=46 or [`u32::MAX`]
    ///
    /// If `highest_bit` is [`u32::MAX`], this means there is no Taken/Not-taken bits.
    #[allow(unused)]
    fn on_long_tnt_packet(
        &mut self,
        context: &DecoderContext,
        packet_bytes: u64,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle TIP packet
    #[allow(unused)]
    fn on_tip_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle TIP.PGD packet
    #[allow(unused)]
    fn on_tip_pgd_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle TIP.PGE packet
    #[allow(unused)]
    fn on_tip_pge_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle FUP packet
    #[allow(unused)]
    fn on_fup_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle PAD packet
    #[allow(unused)]
    fn on_pad_packet(&mut self, context: &DecoderContext) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle CYC packet
    ///
    /// `cyc_packet` is the total content of the CYC packet
    #[allow(unused)]
    fn on_cyc_packet(
        &mut self,
        context: &DecoderContext,
        cyc_packet: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle MODE packet
    ///
    /// `leaf_id` and `mode` is the leaf ID and mode of MODE packet.
    #[allow(unused)]
    fn on_mode_packet(
        &mut self,
        context: &DecoderContext,
        leaf_id: u8,
        mode: u8,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle MTC packet
    ///
    /// `ctc_payload` is the 8-bit CTC payload value
    #[allow(unused)]
    fn on_mtc_packet(
        &mut self,
        context: &DecoderContext,
        ctc_payload: u8,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle TSC packet
    ///
    /// `tsc_value` is the lower 7 bytes of current TSC value
    #[allow(unused)]
    fn on_tsc_packet(
        &mut self,
        context: &DecoderContext,
        tsc_value: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle CBR packet
    ///
    /// `core_bus_ratio` is Core:Bus Ratio
    #[allow(unused)]
    fn on_cbr_packet(
        &mut self,
        context: &DecoderContext,
        core_bus_ratio: u8,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle TMA packet
    ///
    /// `ctc` is CTC[15:0], `fast_counter` is FastCounter[7:0], `fc8` is FC[8]
    #[allow(unused)]
    fn on_tma_packet(
        &mut self,
        context: &DecoderContext,
        ctc: u16,
        fast_counter: u8,
        fc8: bool,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle VMCS packet
    ///
    /// `vmcs_pointer`'s 12..=51 bits are VMCS pointer [51:12] (other bits guaranteed cleared)
    #[allow(unused)]
    fn on_vmcs_packet(
        &mut self,
        context: &DecoderContext,
        vmcs_pointer: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle OVF packet
    #[allow(unused)]
    fn on_ovf_packet(&mut self, context: &DecoderContext) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle PSB packet
    #[allow(unused)]
    fn on_psb_packet(&mut self, context: &DecoderContext) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle PSBEND packet
    #[allow(unused)]
    fn on_psbend_packet(&mut self, context: &DecoderContext) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle TraceStop packet
    #[allow(unused)]
    fn on_trace_stop_packet(&mut self, context: &DecoderContext) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle PIP packet
    ///
    /// `cr3`'s 5..=51 bits are CR3[51:5] (other bits guaranteed cleared),
    /// `rsvd_nr` is RSVD/NR
    #[allow(unused)]
    fn on_pip_packet(
        &mut self,
        context: &DecoderContext,
        cr3: u64,
        rsvd_nr: bool,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle MNT packet
    ///
    /// `payload` is Payload[63:0]
    #[allow(unused)]
    fn on_mnt_packet(&mut self, context: &DecoderContext, payload: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle PTW packet
    ///
    /// `ip_bit` is the IP bit, `payload` is either 4 bytes or 8 bytes
    #[allow(unused)]
    fn on_ptw_packet(
        &mut self,
        context: &DecoderContext,
        ip_bit: bool,
        payload: PtwPayload,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle EXSTOP packet
    ///
    /// `ip_bit` is the IP bit
    #[allow(unused)]
    fn on_exstop_packet(
        &mut self,
        context: &DecoderContext,
        ip_bit: bool,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle MWAIT packet
    ///
    /// `mwait_hints` is MWAIT Hints[7:0], `ext` is EXT[1:0] (upper 6 bits guaranteed cleared)
    #[allow(unused)]
    fn on_mwait_packet(
        &mut self,
        context: &DecoderContext,
        mwait_hints: u8,
        ext: u8,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle PWRE packet
    ///
    /// `hw` is HW, `resolved_thread_c_state` is Resolved Thread C-State (upper 4 bits guaranteed cleared),
    /// `resolved_thread_sub_c_state` is Resolved Thread Sub C-State (upper 4 bits guaranteed cleared)
    #[allow(unused)]
    fn on_pwre_packet(
        &mut self,
        context: &DecoderContext,
        hw: bool,
        resolved_thread_c_state: u8,
        resolved_thread_sub_c_state: u8,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle PWRX packet
    ///
    /// `last_core_c_state` is Last Core C-State (upper 4 bits guaranteed cleared),
    /// `deepest_core_c_state` is Deepest Core C-State (upper 4 bits guaranteed cleared),
    /// `wake_reason` is Wake Reason (upper 4 bits guaranteed cleared)
    #[allow(unused)]
    fn on_pwrx_packet(
        &mut self,
        context: &DecoderContext,
        last_core_c_state: u8,
        deepest_core_c_state: u8,
        wake_reason: u8,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle EVD packet
    ///
    /// `r#type` is Type[5:0] (upper 2 bits guaranteed cleared), `payload` is Payload[63:0]
    #[allow(unused)]
    fn on_evd_packet(
        &mut self,
        context: &DecoderContext,
        r#type: u8,
        payload: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Handle CFE packet
    ///
    /// `ip_bit` is the IP bit, `r#type` is Type[4:0] (upper 3 bits guaranteed cleared),
    /// `vector` is the Vector[7:0]
    #[allow(unused)]
    fn on_cfe_packet(
        &mut self,
        context: &DecoderContext,
        ip_bit: bool,
        r#type: u8,
        vector: u8,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Execution mode
#[derive(Clone, Copy)]
pub enum TraceeMode {
    /// 16-bit mode
    Mode16 = 16,
    /// 32-bit mode
    Mode32 = 32,
    /// 64-bit mode
    Mode64 = 64,
}

impl TraceeMode {
    /// Get the bitness of current tracee mode
    #[must_use]
    pub fn bitness(&self) -> u32 {
        *self as u32
    }
}

/// Decoder context during decoding
pub struct DecoderContext {
    /// Next position in target buffer
    pos: usize,
    /// Current tracee mode (will be modified by MODE.exec packet)
    tracee_mode: TraceeMode,
}

impl DecoderContext {
    /// Get current tracee mode
    #[must_use]
    pub fn tracee_mode(&self) -> TraceeMode {
        self.tracee_mode
    }
}

/// Options for [`decode`].
///
/// You can create default options via [`DecodeOptions::default`].
#[derive(Clone, Copy)]
pub struct DecodeOptions {
    tracee_mode: TraceeMode,
    no_sync: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            tracee_mode: TraceeMode::Mode64,
            no_sync: false,
        }
    }
}

impl DecodeOptions {
    /// Set default mode of tracee before encountering any valid MODE.exec packets.
    ///
    /// Default is [`TraceeMode::Mode64`]
    pub fn tracee_mode(&mut self, tracee_mode: TraceeMode) -> &mut Self {
        self.tracee_mode = tracee_mode;
        self
    }

    /// Set whether the decoder will firstly sync forward for a PSB packet instead of
    /// decoding at 0 offset.
    ///
    /// Default is `true`.
    pub fn sync(&mut self, sync: bool) -> &mut Self {
        self.no_sync = !sync;
        self
    }
}

const PSB_BYTES: [u8; 16] = [
    0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
];

/// Decode the given Intel PT buffer.
///
/// Note that the Linux Perf tool records more than raw Intel PT packets,
/// some sideband data is also recorded. As a result, you need to extract AUX data
/// from the `perf.data` in order to use this method.
///
/// # SAFETY
///
/// We assume that you can never construct a buf whose length can overflow a usize.
/// As a result, we do not check any arithmetic overflow when manipulating the postion
/// of buf cursor (unless you use a debug-build or enable `overflow-checks` in your
/// build profile).
pub fn decode<H: HandlePacket>(
    buf: &[u8],
    options: DecodeOptions,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let DecodeOptions {
        tracee_mode,
        no_sync,
    } = options;

    let start_pos = if no_sync {
        0
    } else {
        let Some(start_pos) = memchr::memmem::find(buf, &PSB_BYTES) else {
            return Err(DecoderError::NoPsb);
        };
        start_pos
    };

    let mut context = DecoderContext {
        pos: start_pos,
        tracee_mode,
    };

    raw_packet_handler::level1::decode(buf, &mut context, packet_handler)
}
