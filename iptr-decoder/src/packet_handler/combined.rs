//! Handler for combining two sub handlers.

use core as std; // workaround for `perfect_derive`

use perfect_derive::perfect_derive;
use thiserror::Error;

use crate::{DecoderContext, HandlePacket, IpReconstructionPattern};

/// A [`HandlePacket`] instance for combining two sub handlers
///
/// Using this struct could leverage the static generic dispatch for
/// maximum performance when you want to use multiple handlers.
///
/// Note that in all packet handle functions, the first handler is executed
/// before the second handler, and if the first handler returns an error,
/// the whole function will directly return without executing the second handler.
pub struct CombinedPacketHandler<H1, H2>
where
    H1: HandlePacket,
    H2: HandlePacket,
{
    handler1: H1,
    handler2: H2,
}

impl<H1, H2> CombinedPacketHandler<H1, H2>
where
    H1: HandlePacket,
    H2: HandlePacket,
{
    /// Create a new [`CombinedPacketHandler`]
    #[must_use]
    pub fn new(handler1: H1, handler2: H2) -> Self {
        Self { handler1, handler2 }
    }

    /// Consume the handler and get the original two handler
    pub fn into_inner(self) -> (H1, H2) {
        (self.handler1, self.handler2)
    }

    /// Get shared reference to handler1
    pub fn handler1(&self) -> &H1 {
        &self.handler1
    }

    /// Get unique reference to handler1
    pub fn handler1_mut(&mut self) -> &mut H1 {
        &mut self.handler1
    }

    /// Get shared reference to handler2
    pub fn handler2(&self) -> &H2 {
        &self.handler2
    }

    /// Get unique reference to handler2
    pub fn handler2_mut(&mut self) -> &mut H2 {
        &mut self.handler2
    }
}

/// Error for [`CombinedPacketHandler`]
#[derive(Error)]
#[perfect_derive(Debug)]
pub enum CombinedError<H1, H2>
where
    H1: HandlePacket,
    H2: HandlePacket,
{
    /// Error of the first handler
    #[error(transparent)]
    H1Error(H1::Error),
    /// Error of the second handler
    #[error(transparent)]
    H2Error(H2::Error),
}

impl<H1, H2> HandlePacket for CombinedPacketHandler<H1, H2>
where
    H1: HandlePacket,
    H2: HandlePacket,
    CombinedError<H1, H2>: core::error::Error,
{
    type Error = CombinedError<H1, H2>;

    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        self.handler1
            .at_decode_begin()
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .at_decode_begin()
            .map_err(CombinedError::H2Error)?;
        Ok(())
    }

    fn on_short_tnt_packet(
        &mut self,
        context: &DecoderContext,
        packet_byte: u8,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_short_tnt_packet(context, packet_byte, highest_bit)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_short_tnt_packet(context, packet_byte, highest_bit)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_long_tnt_packet(
        &mut self,
        context: &DecoderContext,
        packet_bytes: u64,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_long_tnt_packet(context, packet_bytes, highest_bit)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_long_tnt_packet(context, packet_bytes, highest_bit)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_tip_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_tip_packet(context, ip_reconstruction_pattern)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_tip_packet(context, ip_reconstruction_pattern)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_tip_pgd_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_tip_pgd_packet(context, ip_reconstruction_pattern)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_tip_pgd_packet(context, ip_reconstruction_pattern)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_tip_pge_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_tip_pge_packet(context, ip_reconstruction_pattern)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_tip_pge_packet(context, ip_reconstruction_pattern)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_fup_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_fup_packet(context, ip_reconstruction_pattern)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_fup_packet(context, ip_reconstruction_pattern)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_pad_packet(&mut self, context: &DecoderContext) -> Result<(), Self::Error> {
        self.handler1
            .on_pad_packet(context)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_pad_packet(context)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_cyc_packet(
        &mut self,
        context: &DecoderContext,
        cyc_packet: &[u8],
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_cyc_packet(context, cyc_packet)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_cyc_packet(context, cyc_packet)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_mode_packet(
        &mut self,
        context: &DecoderContext,
        leaf_id: u8,
        mode: u8,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_mode_packet(context, leaf_id, mode)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_mode_packet(context, leaf_id, mode)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_mtc_packet(
        &mut self,
        context: &DecoderContext,
        ctc_payload: u8,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_mtc_packet(context, ctc_payload)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_mtc_packet(context, ctc_payload)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_tsc_packet(
        &mut self,
        context: &DecoderContext,
        tsc_value: u64,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_tsc_packet(context, tsc_value)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_tsc_packet(context, tsc_value)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_cbr_packet(
        &mut self,
        context: &DecoderContext,
        core_bus_ratio: u8,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_cbr_packet(context, core_bus_ratio)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_cbr_packet(context, core_bus_ratio)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_tma_packet(
        &mut self,
        context: &DecoderContext,
        ctc: u16,
        fast_counter: u8,
        fc8: bool,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_tma_packet(context, ctc, fast_counter, fc8)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_tma_packet(context, ctc, fast_counter, fc8)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_vmcs_packet(
        &mut self,
        context: &DecoderContext,
        vmcs_pointer: u64,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_vmcs_packet(context, vmcs_pointer)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_vmcs_packet(context, vmcs_pointer)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_ovf_packet(&mut self, context: &DecoderContext) -> Result<(), Self::Error> {
        self.handler1
            .on_ovf_packet(context)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_ovf_packet(context)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_psb_packet(&mut self, context: &DecoderContext) -> Result<(), Self::Error> {
        self.handler1
            .on_psb_packet(context)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_psb_packet(context)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_psbend_packet(&mut self, context: &DecoderContext) -> Result<(), Self::Error> {
        self.handler1
            .on_psbend_packet(context)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_psbend_packet(context)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_trace_stop_packet(&mut self, context: &DecoderContext) -> Result<(), Self::Error> {
        self.handler1
            .on_trace_stop_packet(context)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_trace_stop_packet(context)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_pip_packet(
        &mut self,
        context: &DecoderContext,
        cr3: u64,
        rsvd_nr: bool,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_pip_packet(context, cr3, rsvd_nr)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_pip_packet(context, cr3, rsvd_nr)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_mnt_packet(&mut self, context: &DecoderContext, payload: u64) -> Result<(), Self::Error> {
        self.handler1
            .on_mnt_packet(context, payload)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_mnt_packet(context, payload)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_ptw_packet(
        &mut self,
        context: &DecoderContext,
        ip_bit: bool,
        payload: crate::PtwPayload,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_ptw_packet(context, ip_bit, payload)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_ptw_packet(context, ip_bit, payload)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_exstop_packet(
        &mut self,
        context: &DecoderContext,
        ip_bit: bool,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_exstop_packet(context, ip_bit)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_exstop_packet(context, ip_bit)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_mwait_packet(
        &mut self,
        context: &DecoderContext,
        mwait_hints: u8,
        ext: u8,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_mwait_packet(context, mwait_hints, ext)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_mwait_packet(context, mwait_hints, ext)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_pwre_packet(
        &mut self,
        context: &DecoderContext,
        hw: bool,
        resolved_thread_c_state: u8,
        resolved_thread_sub_c_state: u8,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_pwre_packet(
                context,
                hw,
                resolved_thread_c_state,
                resolved_thread_sub_c_state,
            )
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_pwre_packet(
                context,
                hw,
                resolved_thread_c_state,
                resolved_thread_sub_c_state,
            )
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_pwrx_packet(
        &mut self,
        context: &DecoderContext,
        last_core_c_state: u8,
        deepest_core_c_state: u8,
        wake_reason: u8,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_pwrx_packet(
                context,
                last_core_c_state,
                deepest_core_c_state,
                wake_reason,
            )
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_pwrx_packet(
                context,
                last_core_c_state,
                deepest_core_c_state,
                wake_reason,
            )
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_evd_packet(
        &mut self,
        context: &DecoderContext,
        r#type: u8,
        payload: u64,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_evd_packet(context, r#type, payload)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_evd_packet(context, r#type, payload)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }

    fn on_cfe_packet(
        &mut self,
        context: &DecoderContext,
        ip_bit: bool,
        r#type: u8,
        vector: u8,
    ) -> Result<(), Self::Error> {
        self.handler1
            .on_cfe_packet(context, ip_bit, r#type, vector)
            .map_err(CombinedError::H1Error)?;
        self.handler2
            .on_cfe_packet(context, ip_bit, r#type, vector)
            .map_err(CombinedError::H2Error)?;

        Ok(())
    }
}
