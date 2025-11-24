#![no_std]

pub mod error;
mod raw_packet_handler;

pub use raw_packet_handler::{level1::IpReconstructionPattern, level2::PtwPayload};

use crate::error::{DecoderError, DecoderResult};

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
    fn on_short_tnt_packet(&mut self, packet_byte: u8, highest_bit: u32)
    -> Result<(), Self::Error>;

    /// Handle short TNT packet
    ///
    /// `packet_bytes` is the whole 6 bytes of long TNT packet payload. The
    /// upper 2 bytes are guaranteed to be cleared.
    /// `highest_bit` is the index of highest bit that represents a valid
    /// Taken/Not-taken bit, guaranteed to be in range 0..=46 or u32::MAX
    ///
    /// If `highest_bit` is u32::MAX, this means there is no Taken/Not-taken bits.
    fn on_long_tnt_packet(
        &mut self,
        packet_bytes: u64,
        highest_bit: u32,
    ) -> Result<(), Self::Error>;

    /// Handle TIP packet
    fn on_tip_packet(
        &mut self,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error>;

    /// Handle TIP.PGD packet
    fn on_tip_pgd_packet(
        &mut self,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error>;

    /// Handle TIP.PGE packet
    fn on_tip_pge_packet(
        &mut self,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error>;

    /// Handle FUP packet
    fn on_fup_packet(
        &mut self,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error>;

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

    /// Handle CBR packet
    ///
    /// `core_bus_ratio` is Core:Bus Ratio
    fn on_cbr_packet(&mut self, core_bus_ratio: u8) -> Result<(), Self::Error>;

    /// Handle TMA packet
    ///
    /// `ctc` is CTC[15:0], `fast_counter` is FastCounter[7:0], `fc8` is FC[8]
    fn on_tma_packet(&mut self, ctc: u16, fast_counter: u8, fc8: bool) -> Result<(), Self::Error>;

    /// Handle VMCS packet
    ///
    /// `vmcs_pointer`'s 12..=51 bits are VMCS pointer [51:12] (other bits guaranteed cleared)
    fn on_vmcs_packet(&mut self, vmcs_pointer: u64) -> Result<(), Self::Error>;

    /// Handle OVF packet
    fn on_ovf_packet(&mut self) -> Result<(), Self::Error>;

    /// Handle PSB packet
    fn on_psb_packet(&mut self) -> Result<(), Self::Error>;

    /// Handle PSBEND packet
    fn on_psbend_packet(&mut self) -> Result<(), Self::Error>;

    /// Handle TraceStop packet
    fn on_trace_stop_packet(&mut self) -> Result<(), Self::Error>;

    /// Handle PIP packet
    ///
    /// `cr3`'s 5..=51 bits are CR3[51:5] (other bits guaranteed cleared),
    /// `rsvd_nr` is RSVD/NR
    fn on_pip_packet(&mut self, cr3: u64, rsvd_nr: bool) -> Result<(), Self::Error>;

    /// Handle MNT packet
    ///
    /// `payload` is Payload[63:0]
    fn on_mnt_packet(&mut self, payload: u64) -> Result<(), Self::Error>;

    /// Handle PTW packet
    ///
    /// `ip_bit` is the IP bit, `payload` is either 4 bytes or 8 bytes
    fn on_ptw_packet(&mut self, ip_bit: bool, payload: PtwPayload) -> Result<(), Self::Error>;

    /// Handle EXSTOP packet
    ///
    /// `ip_bit` is the IP bit
    fn on_exstop_packet(&mut self, ip_bit: bool) -> Result<(), Self::Error>;

    /// Handle MWAIT packet
    ///
    /// `mwait_hints` is MWAIT Hints[7:0], `ext` is EXT[1:0] (upper 6 bits guaranteed cleared)
    fn on_mwait_packet(&mut self, mwait_hints: u8, ext: u8) -> Result<(), Self::Error>;

    /// Handle PWRE packet
    ///
    /// `hw` is HW, `resolved_thread_c_state` is Resolved Thread C-State (upper 4 bits guaranteed cleared),
    /// `resolved_thread_sub_c_state` is Resolved Thread Sub C-State (upper 4 bits guaranteed cleared)
    fn on_pwre_packet(
        &mut self,
        hw: bool,
        resolved_thread_c_state: u8,
        resolved_thread_sub_c_state: u8,
    ) -> Result<(), Self::Error>;

    /// Handle PWRX packet
    ///
    /// `last_core_c_state` is Last Core C-State (upper 4 bits guaranteed cleared),
    /// `deepest_core_c_state` is Deepest Core C-State (upper 4 bits guaranteed cleared),
    /// `wake_reason` is Wake Reason (upper 4 bits guaranteed cleared)
    fn on_pwrx_packet(
        &mut self,
        last_core_c_state: u8,
        deepest_core_c_state: u8,
        wake_reason: u8,
    ) -> Result<(), Self::Error>;

    /// Handle EVD packet
    ///
    /// `r#type` is Type[5:0] (upper 2 bits guaranteed cleared), `payload` is Payload[63:0]
    fn on_evd_packet(&mut self, r#type: u8, payload: u64) -> Result<(), Self::Error>;

    /// Handle CFE packet
    ///
    /// `ip_bit` is the IP bit, `r#type` is Type[4:0] (upper 3 bits guaranteed cleared),
    /// `vector` is the Vector[7:0]
    fn on_cfe_packet(&mut self, ip_bit: bool, r#type: u8, vector: u8) -> Result<(), Self::Error>;
}

/// Execution mode
#[derive(Clone, Copy)]
pub enum TraceeMode {
    Mode64,
    Mode32,
    Mode16,
}

struct DecoderContext {
    pos: usize,
    tracee_mode: TraceeMode,
}

/// Options for [`decode`].
///
/// You can create default options via [`DecodeOptions::default`].
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

/// Decode the given Intel PT buffer.
///
/// Note that the Linux Perf tool records more than raw Intel PT packets,
/// some sideband data is also recorded. As a result, you need to extract AUX data
/// from the `perf.data` in order to use this method.
pub fn decode<H: HandlePacket>(
    buf: &[u8],
    options: DecodeOptions,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let DecodeOptions {
        tracee_mode,
        no_sync,
    } = options;

    const PSB_BYTES: [u8; 16] = [
        0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02,
        0x82,
    ];

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
