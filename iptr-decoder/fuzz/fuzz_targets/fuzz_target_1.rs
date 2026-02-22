#![no_main]

use iptr_decoder::{DecodeOptions, HandlePacket};
use libfuzzer_sys::fuzz_target;

struct FuzzHandlePacket;

impl HandlePacket for FuzzHandlePacket {
    type Error = std::convert::Infallible;

    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn on_short_tnt_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        packet_byte: std::num::NonZero<u8>,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(packet_byte);
        let _ = std::hint::black_box(highest_bit);
        Ok(())
    }

    fn on_long_tnt_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        packet_bytes: std::num::NonZero<u64>,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(packet_bytes);
        let _ = std::hint::black_box(highest_bit);
        Ok(())
    }

    fn on_tip_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        ip_reconstruction_pattern: iptr_decoder::IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(ip_reconstruction_pattern);
        Ok(())
    }

    fn on_tip_pgd_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        ip_reconstruction_pattern: iptr_decoder::IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(ip_reconstruction_pattern);
        Ok(())
    }

    fn on_tip_pge_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        ip_reconstruction_pattern: iptr_decoder::IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(ip_reconstruction_pattern);
        Ok(())
    }

    fn on_fup_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        ip_reconstruction_pattern: iptr_decoder::IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(ip_reconstruction_pattern);
        Ok(())
    }

    fn on_pad_packet(&mut self, context: &iptr_decoder::DecoderContext) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        Ok(())
    }

    fn on_cyc_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        cyc_packet: &[u8],
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        touched::touching(cyc_packet);
        Ok(())
    }

    fn on_mode_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        leaf_id: u8,
        mode: u8,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(leaf_id);
        let _ = std::hint::black_box(mode);
        Ok(())
    }

    fn on_mtc_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        ctc_payload: u8,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(ctc_payload);
        Ok(())
    }

    fn on_tsc_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        tsc_value: u64,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(tsc_value);
        Ok(())
    }

    fn on_cbr_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        core_bus_ratio: u8,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(core_bus_ratio);
        Ok(())
    }

    fn on_tma_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        ctc: u16,
        fast_counter: u8,
        fc8: bool,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(ctc);
        let _ = std::hint::black_box(fast_counter);
        let _ = std::hint::black_box(fc8);
        Ok(())
    }

    fn on_vmcs_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        vmcs_pointer: u64,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(vmcs_pointer);
        Ok(())
    }

    fn on_ovf_packet(&mut self, context: &iptr_decoder::DecoderContext) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        Ok(())
    }

    fn on_psb_packet(&mut self, context: &iptr_decoder::DecoderContext) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        Ok(())
    }

    fn on_psbend_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        Ok(())
    }

    fn on_trace_stop_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        Ok(())
    }

    fn on_pip_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        cr3: u64,
        rsvd_nr: bool,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(cr3);
        let _ = std::hint::black_box(rsvd_nr);
        Ok(())
    }

    fn on_mnt_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        payload: u64,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(payload);
        Ok(())
    }

    fn on_ptw_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        ip_bit: bool,
        payload: iptr_decoder::PtwPayload,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(ip_bit);
        let _ = std::hint::black_box(payload);
        Ok(())
    }

    fn on_exstop_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        ip_bit: bool,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(ip_bit);
        Ok(())
    }

    fn on_mwait_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        mwait_hints: u8,
        ext: u8,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(mwait_hints);
        let _ = std::hint::black_box(ext);
        Ok(())
    }

    fn on_pwre_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        hw: bool,
        resolved_thread_c_state: u8,
        resolved_thread_sub_c_state: u8,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(hw);
        let _ = std::hint::black_box(resolved_thread_c_state);
        let _ = std::hint::black_box(resolved_thread_sub_c_state);
        Ok(())
    }

    fn on_pwrx_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        last_core_c_state: u8,
        deepest_core_c_state: u8,
        wake_reason: u8,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(last_core_c_state);
        let _ = std::hint::black_box(deepest_core_c_state);
        let _ = std::hint::black_box(wake_reason);
        Ok(())
    }

    fn on_evd_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        r#type: u8,
        payload: u64,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(r#type);
        let _ = std::hint::black_box(payload);
        Ok(())
    }

    fn on_cfe_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        ip_bit: bool,
        r#type: u8,
        vector: u8,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(ip_bit);
        let _ = std::hint::black_box(r#type);
        let _ = std::hint::black_box(vector);
        Ok(())
    }

    fn on_bbp_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        sz_bit: bool,
        r#type: u8,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(sz_bit);
        let _ = std::hint::black_box(r#type);
        Ok(())
    }

    fn on_bep_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        ip_bit: bool,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(ip_bit);
        Ok(())
    }

    fn on_bip_packet(
        &mut self,
        context: &iptr_decoder::DecoderContext,
        id: u8,
        payload: &[u8],
        bbp_type: u8,
    ) -> Result<(), Self::Error> {
        let _ = std::hint::black_box(context);
        let _ = std::hint::black_box(id);
        touched::touching(payload);
        let _ = std::hint::black_box(bbp_type);
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = iptr_decoder::decode(data, DecodeOptions::default(), &mut FuzzHandlePacket);
});
