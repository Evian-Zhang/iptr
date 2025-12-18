mod control_flow_cache;
mod control_flow_handler;
pub mod error;
mod memory_reader;
mod static_analyzer;
mod tnt_buffer;

use std::num::NonZero;

use iptr_decoder::{DecoderContext, HandlePacket, IpReconstructionPattern};

use crate::{
    control_flow_cache::ControlFlowCacheManager,
    error::{AnalyzerError, AnalyzerResult},
    static_analyzer::StaticControlFlowAnalyzer,
    tnt_buffer::TntBufferManager,
};
pub use crate::{
    control_flow_handler::{ControlFlowTransitionKind, HandleControlFlow},
    memory_reader::ReadMemory,
};

/// TNT bits processing status
#[derive(Clone, Copy, Debug)]
enum TntProceed {
    /// During the process of current TNT bits, there
    /// is no deferred TIP detected
    Continue,
    /// During the process of current TNT bits, a deferred
    /// TIP is detected.
    Break {
        /// Before this deferred TIP, there are already this number
        /// of TNT bits processed.
        processed_bit_count: u32,
        /// Reason for the deferred TIP.
        ///
        /// This can reduce the number of CFG resolutions.
        pre_tip_status: PreTipStatus,
    },
}

/// Status for determining the semantic of next TIP packet
#[derive(Clone, Copy, Debug)]
enum PreTipStatus {
    /// There is nothing related to the next TIP packet, or
    /// the status is not yet determined
    ///
    /// For example, after the last TNT bit, the next CFG
    /// node is still a direct branch. In this case, no TIP packet
    /// status is forced.
    Normal,
    /// The next CFG node is a RET instruction. Since we have
    /// disabled return compression, the next TIP packet will always
    /// be the return address.
    PendingReturn,
    /// The next CFG node is an indirect JMP instruction.
    PendingIndirectGoto,
    /// The next CFG node is an indirect CALL instruction.
    PendingIndirectCall,
    /// The next CFG node is a far transfer instruction such as SYSCALL
    PendingFarTransfer,
    /// There is a FUP packet before this packet. So there must be
    /// a TIP or TIP.PGD packet.
    PendingFup,
    /// There is an OVF packet before this packet. So there must be
    /// a FUP, TIP or TIP.PGE packet.
    PendingOvf,
}

/// An edge analyzer that implements [`HandlePacket`] trait.
///
/// The analyzer will trace the control flow during the Intel PT packets, and invoke
/// corresponding callbacks in the given control flow handler that implements
/// [`HandleControlFlow`].
pub struct EdgeAnalyzer<'a, H: HandleControlFlow, R: ReadMemory> {
    /// IP-reconstruction-specific field.
    ///
    /// This is not always be the last IP in the packet. It has
    /// special semantic according to Intel. Do not use thie field
    /// until you know what you are doing.
    last_ip: u64,
    /// Address of previous basic block
    ///
    /// Instruction address will never be zero
    ///
    /// # Important Notes
    ///
    /// This field is only accessed in the handler methods in [`HandlePacket`].
    /// For performance consideration, this field will never be updated during
    /// internal parsing methods such as [`handle_tnt_buffer32`][Self::handle_tnt_buffer32].
    /// As a result, you should never read this field in those methods.
    last_bb: Option<NonZero<u64>>,
    /// Status of the next TIP packet.
    pre_tip_status: PreTipStatus,
    /// Buffering the TNT bits for better cache.
    tnt_buffer_manager: TntBufferManager,
    /// Caches used to speed up TNT bits resolution without querying the CFG.
    cache_manager: ControlFlowCacheManager<Option<H::CachedKey>>,
    /// CFG node maintainer
    static_analyzer: StaticControlFlowAnalyzer,
    /// Passed control flow handler
    handler: &'a mut H,
    /// Passed memory reader
    reader: &'a mut R,
}

impl<'a, H: HandleControlFlow, R: ReadMemory> EdgeAnalyzer<'a, H, R> {
    /// Create a new edge analyzer
    #[must_use]
    pub fn new(handler: &'a mut H, reader: &'a mut R) -> Self {
        Self {
            last_ip: 0,
            last_bb: None,
            pre_tip_status: PreTipStatus::Normal,
            tnt_buffer_manager: TntBufferManager::new(),
            cache_manager: ControlFlowCacheManager::new(),
            static_analyzer: StaticControlFlowAnalyzer::new(),
            handler,
            reader,
        }
    }

    /// Perform IP reconstruction and update the `last_ip` field,
    /// returns the full-width IP address
    #[expect(
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::enum_glob_use
    )]
    fn reconstruct_ip_and_update_last(
        &mut self,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Option<u64> {
        use IpReconstructionPattern::*;
        let ip = match ip_reconstruction_pattern {
            OutOfContext => {
                // `last_ip` is not updated
                return None;
            }
            TwoBytesWithLastIp(payload) => {
                (self.last_ip & 0xFFFF_FFFF_FFFF_0000) | (payload as u64)
            }
            FourBytesWithLastIp(payload) => {
                (self.last_ip & 0xFFFF_FFFF_0000_0000) | (payload as u64)
            }
            SixBytesExtended(payload) => (((payload << 16) as i64) >> 16) as u64,
            SixBytesWithLastIp(payload) => {
                (self.last_ip & 0xFFFF_0000_0000_0000) | (payload as u64)
            }
            EightBytes(payload) => payload,
        };
        self.last_ip = ip;

        Some(ip)
    }

    /// Process the given TNT bit, querying the CFG graph without
    /// using any cache.
    ///
    /// This function will return a tuple `(cached_key, tnt_proceed)` on success.
    /// The return value is similar to [`handle_tnt_buffer8`][Self::handle_tnt_buffer8].
    ///
    /// Note that this function does not detect infinite loop
    #[expect(
        clippy::enum_glob_use,
        clippy::items_after_statements,
        clippy::needless_continue
    )]
    fn process_tnt_bit_without_cache(
        &mut self,
        context: &DecoderContext,
        last_bb_ref: &mut u64,
        is_taken: bool,
    ) -> AnalyzerResult<(Option<H::CachedKey>, TntProceed), H, R> {
        let mut last_bb = *last_bb_ref;
        let mut cached_key = None;
        let tnt_proceed;
        'cfg_traverse: loop {
            let cfg_node =
                self.static_analyzer
                    .resolve(self.reader, context.tracee_mode(), last_bb)?;
            let terminator = cfg_node.terminator;
            use static_analyzer::CfgTerminator::*;
            match terminator {
                Branch { r#true, r#false } => {
                    last_bb = if is_taken { r#true } else { r#false };
                    let new_cached_key = self
                        .handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::ConditionalBranch)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    control_flow_cache::update_cached_key(
                        self.handler,
                        &mut cached_key,
                        new_cached_key,
                    )?;
                    tnt_proceed = TntProceed::Continue;
                    break 'cfg_traverse;
                }
                DirectGoto { target } => {
                    last_bb = target;
                    let new_cached_key = self
                        .handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::DirectJump)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    control_flow_cache::update_cached_key(
                        self.handler,
                        &mut cached_key,
                        new_cached_key,
                    )?;
                    continue 'cfg_traverse;
                }
                DirectCall {
                    target,
                    return_address: _,
                } => {
                    last_bb = target;
                    let new_cached_key = self
                        .handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::DirectCall)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    control_flow_cache::update_cached_key(
                        self.handler,
                        &mut cached_key,
                        new_cached_key,
                    )?;
                    continue 'cfg_traverse;
                }
                IndirectGoto => {
                    // Wait for deferred TIP
                    tnt_proceed = TntProceed::Break {
                        processed_bit_count: 0,
                        pre_tip_status: PreTipStatus::PendingIndirectGoto,
                    };
                    break 'cfg_traverse;
                }
                IndirectCall => {
                    // Wait for deferred TIP
                    tnt_proceed = TntProceed::Break {
                        processed_bit_count: 0,
                        pre_tip_status: PreTipStatus::PendingIndirectCall,
                    };
                    break 'cfg_traverse;
                }
                NearRet => {
                    if !is_taken {
                        // If return is not compressed, then an immediate TIP packet will be generated.
                        // If return is compressed, then a taken bit will be generated
                        return Err(AnalyzerError::InvalidPacket);
                    }
                    return Err(AnalyzerError::UnsupportedReturnCompression);
                    // update_cached_key(self.handler, &mut cached_key, new_cached_key)?;
                }
                FarTransfers {
                    next_instruction: _,
                } => {
                    // Wait for deferred TIP
                    tnt_proceed = TntProceed::Break {
                        processed_bit_count: 0,
                        pre_tip_status: PreTipStatus::PendingFarTransfer,
                    };
                    break 'cfg_traverse;
                }
            }
        }
        *last_bb_ref = last_bb;

        Ok((cached_key, tnt_proceed))
    }

    /// Determine the status of the next TIP packet.
    ///
    /// This function is invoked upon a TIP packet is arrived and current
    /// `pre_tip_status` is just normal (which means the previous TNT bits
    /// have not met the deferred TIP). In this case, we need to check the
    /// last CFG node for proper control flow handler invocation.
    #[expect(
        clippy::enum_glob_use,
        clippy::items_after_statements,
        clippy::needless_continue
    )]
    fn determine_pre_tip_status(&mut self, context: &DecoderContext) -> AnalyzerResult<(), H, R> {
        let Some(last_bb) = self.last_bb else {
            // No previous instruction
            return Ok(());
        };
        let mut last_bb = last_bb.get();
        'cfg_traverse: loop {
            let cfg_node =
                self.static_analyzer
                    .resolve(self.reader, context.tracee_mode(), last_bb)?;
            let terminator = cfg_node.terminator;
            use static_analyzer::CfgTerminator::*;
            match terminator {
                Branch { .. } => {
                    // It's really normal.
                    break 'cfg_traverse;
                }
                DirectGoto { target } => {
                    last_bb = target;
                    let _new_cached_key = self
                        .handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::DirectJump)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    continue 'cfg_traverse;
                }
                DirectCall {
                    target,
                    return_address: _,
                } => {
                    last_bb = target;
                    let _new_cached_key = self
                        .handler
                        .on_new_block(last_bb, ControlFlowTransitionKind::DirectCall)
                        .map_err(AnalyzerError::ControlFlowHandler)?;
                    continue 'cfg_traverse;
                }
                IndirectGoto => {
                    self.pre_tip_status = PreTipStatus::PendingIndirectGoto;
                    break 'cfg_traverse;
                }
                IndirectCall => {
                    self.pre_tip_status = PreTipStatus::PendingIndirectCall;
                    break 'cfg_traverse;
                }
                NearRet => {
                    self.pre_tip_status = PreTipStatus::PendingReturn;
                    break 'cfg_traverse;
                }
                FarTransfers {
                    next_instruction: _,
                } => {
                    self.pre_tip_status = PreTipStatus::PendingFarTransfer;
                    break 'cfg_traverse;
                }
            }
        }

        Ok(())
    }

    /// Process all remaining TNT bits inside tnt buffer manager
    fn process_all_pending_tnts(&mut self, context: &DecoderContext) -> AnalyzerResult<(), H, R> {
        let Some(last_bb) = self.last_bb else {
            return Ok(());
        };
        // There are already some valid TNT packets here since
        // last_bb is not uninitialized
        let mut last_bb = last_bb.get();
        // Clear the pending tnt buffers.
        let tnt_buffer = self.tnt_buffer_manager.take();
        let res = self.handle_maybe_full_tnt_buffer(context, &mut last_bb, tnt_buffer);
        self.last_bb = NonZero::new(last_bb);
        res
    }

    /// Handle TIP or TIP.PGD since TIP.PGD can replace TIP packets if
    /// the destination goes out of ranges.
    #[expect(clippy::redundant_else)]
    fn handle_tip_or_tip_pgd_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
        is_pgd: bool,
    ) -> AnalyzerResult<(), H, R> {
        if matches!(self.pre_tip_status, PreTipStatus::Normal) {
            self.determine_pre_tip_status(context)?;
        }
        if matches!(self.pre_tip_status, PreTipStatus::Normal) {
            // This will also refresh pre_tip_status, which
            // can avoid non-deferred TIPs
            self.process_all_pending_tnts(context)?;
        }
        let Some(new_last_bb) = self.reconstruct_ip_and_update_last(ip_reconstruction_pattern)
        else {
            // Out-of-context IP
            if is_pgd {
                // SYSCALL into kernel codes...
                self.pre_tip_status = PreTipStatus::Normal;
                return Ok(());
            } else {
                // Single TIP packet emit a out-of-context IP?
                return Err(AnalyzerError::InvalidPacket);
            }
        };
        self.last_bb = NonZero::new(new_last_bb);
        match self.pre_tip_status {
            PreTipStatus::Normal => {
                let _new_cached_key = self
                    .handler
                    .on_new_block(new_last_bb, ControlFlowTransitionKind::NewBlock)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
            }
            PreTipStatus::PendingReturn => {
                let _new_cached_key = self
                    .handler
                    .on_new_block(new_last_bb, ControlFlowTransitionKind::Return)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
                self.pre_tip_status = PreTipStatus::Normal;
            }
            PreTipStatus::PendingIndirectGoto => {
                let _new_cached_key = self
                    .handler
                    .on_new_block(new_last_bb, ControlFlowTransitionKind::IndirectJump)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
                self.pre_tip_status = PreTipStatus::Normal;
            }
            PreTipStatus::PendingIndirectCall => {
                let _new_cached_key = self
                    .handler
                    .on_new_block(new_last_bb, ControlFlowTransitionKind::IndirectCall)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
                self.pre_tip_status = PreTipStatus::Normal;
            }
            PreTipStatus::PendingFarTransfer => {
                let _new_cached_key = self
                    .handler
                    .on_new_block(new_last_bb, ControlFlowTransitionKind::NewBlock)
                    .map_err(AnalyzerError::ControlFlowHandler)?;
                self.pre_tip_status = PreTipStatus::Normal;
            }
            PreTipStatus::PendingFup => {
                self.pre_tip_status = PreTipStatus::Normal;
                self.tnt_buffer_manager.clear();
                return Ok(());
            }
            PreTipStatus::PendingOvf => {
                // OVF should be followed by FUP or TIP.PGE
                return Err(AnalyzerError::InvalidPacket);
            }
        }

        Ok(())
    }
}

impl<H, R> HandlePacket for EdgeAnalyzer<'_, H, R>
where
    H: HandleControlFlow,
    R: ReadMemory,
    AnalyzerError<H, R>: std::error::Error,
{
    type Error = AnalyzerError<H, R>;

    fn on_short_tnt_packet(
        &mut self,
        context: &DecoderContext,
        packet_byte: u8,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        if highest_bit == 0 {
            // No TNT bits
            return Ok(());
        }
        let Some(last_bb) = self.last_bb else {
            // No previous TIP given. Silently ignore those TNTs
            return Ok(());
        };
        let mut last_bb = last_bb.get();
        if let Some(full_tnt_buffer) = self.tnt_buffer_manager.extend_with_short_tnt(packet_byte) {
            let res = self.handle_full_tnt_buffer(context, &mut last_bb, full_tnt_buffer);
            self.last_bb = NonZero::new(last_bb);
            res?;
        }

        Ok(())
    }

    fn on_long_tnt_packet(
        &mut self,
        context: &DecoderContext,
        packet_bytes: u64,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        if highest_bit == u32::MAX {
            // No TNT bits
            return Ok(());
        }
        let Some(last_bb) = self.last_bb else {
            // No previous TIP given. Silently ignore those TNTs
            return Ok(());
        };
        let mut last_bb = last_bb.get();
        if let Some(full_tnt_buffer) = self.tnt_buffer_manager.extend_with_long_tnt(packet_bytes) {
            let res = self.handle_full_tnt_buffer(context, &mut last_bb, full_tnt_buffer);
            self.last_bb = NonZero::new(last_bb);
            res?;
        }

        Ok(())
    }

    fn on_tip_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        self.handle_tip_or_tip_pgd_packet(context, ip_reconstruction_pattern, false)?;
        Ok(())
    }

    fn on_tip_pgd_packet(
        &mut self,
        context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        self.handle_tip_or_tip_pgd_packet(context, ip_reconstruction_pattern, true)?;

        self.last_bb = None;
        self.tnt_buffer_manager.clear();
        Ok(())
    }

    fn on_tip_pge_packet(
        &mut self,
        _context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        if matches!(self.pre_tip_status, PreTipStatus::PendingOvf) {
            let Some(last_bb) = self.reconstruct_ip_and_update_last(ip_reconstruction_pattern)
            else {
                // Any IP compression that follows the OVF is guaranteed to
                // use as a reference `LastIP` the IP payload of an IP packet
                return Err(AnalyzerError::InvalidPacket);
            };
            self.last_bb = NonZero::new(last_bb);
            self.pre_tip_status = PreTipStatus::Normal;
            self.tnt_buffer_manager.clear();
            let _new_cached_key = self
                .handler
                .on_new_block(last_bb, ControlFlowTransitionKind::NewBlock)
                .map_err(AnalyzerError::ControlFlowHandler)?;
            return Ok(());
        }
        if let Some(last_bb) = self.reconstruct_ip_and_update_last(ip_reconstruction_pattern) {
            self.last_bb = NonZero::new(last_bb);
            let _new_cached_key = self
                .handler
                .on_new_block(last_bb, ControlFlowTransitionKind::NewBlock)
                .map_err(AnalyzerError::ControlFlowHandler)?;
        }
        self.pre_tip_status = PreTipStatus::Normal;
        self.tnt_buffer_manager.clear();

        Ok(())
    }

    fn on_fup_packet(
        &mut self,
        _context: &DecoderContext,
        ip_reconstruction_pattern: IpReconstructionPattern,
    ) -> Result<(), Self::Error> {
        if matches!(self.pre_tip_status, PreTipStatus::PendingOvf) {
            self.pre_tip_status = PreTipStatus::Normal;
            let Some(last_bb) = self.reconstruct_ip_and_update_last(ip_reconstruction_pattern)
            else {
                // Any IP compression that follows the OVF is guaranteed to
                // use as a reference `LastIP` the IP payload of an IP packet
                return Err(AnalyzerError::InvalidPacket);
            };
            self.last_bb = NonZero::new(last_bb);
            self.tnt_buffer_manager.clear();

            return Ok(());
        }
        self.reconstruct_ip_and_update_last(ip_reconstruction_pattern);
        self.pre_tip_status = PreTipStatus::PendingFup;

        Ok(())
    }

    fn on_ovf_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        self.pre_tip_status = PreTipStatus::PendingOvf;
        Ok(())
    }

    fn on_psb_packet(&mut self, _context: &DecoderContext) -> Result<(), Self::Error> {
        self.last_bb = None;
        self.last_ip = 0;
        self.pre_tip_status = PreTipStatus::Normal;
        self.tnt_buffer_manager.clear();

        Ok(())
    }
}
