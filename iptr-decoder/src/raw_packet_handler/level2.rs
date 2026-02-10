use core::{hint::unreachable_unchecked, num::NonZero};

use derive_more::Display;

use crate::{
    DecoderContext, HandlePacket, PacketBlockInformation, PacketBlockSize,
    error::{DecoderError, DecoderResult},
};

#[inline]
fn handle_cbr_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 4;

    let Some(core_bus_ratio) = buf.get(context.pos + 2) else {
        return Err(DecoderError::UnexpectedEOF);
    };
    packet_handler
        .on_cbr_packet(context, *core_bus_ratio)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_pip_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 8;

    let Some([byte2, byte3, byte4, byte5, byte6, byte7]) = buf
        .get((context.pos + 2)..)
        .and_then(|buf| buf.first_chunk::<6>())
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let rsvd_nr = (*byte2 % 2) != 0;
    let byte2 = *byte2 & 0b1111_1110; // Clear lowest bit
    let cr3 = u64::from_le_bytes([byte2, *byte3, *byte4, *byte5, *byte6, *byte7, 0, 0]) << 5;

    packet_handler
        .on_pip_packet(context, cr3, rsvd_nr)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[expect(clippy::unreadable_literal)]
const PSB: u128 = 0x82028202820282028202820282028202;

#[inline]
fn handle_psb_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 16;

    let Some(bytes) = buf
        .get(context.pos..)
        .and_then(|buf| buf.first_chunk::<16>())
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let psb = u128::from_le_bytes(*bytes);
    if psb != PSB {
        return Err(DecoderError::InvalidPacket);
    }

    packet_handler
        .on_psb_packet(context)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_psbend_packet<H: HandlePacket>(
    _buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    packet_handler
        .on_psbend_packet(context)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_trace_stop_packet<H: HandlePacket>(
    _buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    packet_handler
        .on_trace_stop_packet(context)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
#[expect(clippy::int_plus_one)]
fn handle_long_tnt_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 8;

    let Some(bytes) = buf
        .get(context.pos..)
        .and_then(|buf| buf.first_chunk::<8>())
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let packet = u64::from_le_bytes(*bytes);
    let leading_zeros = packet.leading_zeros();
    if leading_zeros == 64 - 16 {
        // There is no trailing 1
        return Err(DecoderError::InvalidPacket);
    }
    let packet_bytes = packet >> 16;
    // SAFETY: Trailing 1 guarantees the nonzero
    let packet_bytes = unsafe { NonZero::new_unchecked(packet_bytes) };

    // Leading zeros must <= 64-16. And we have checked it is not equal
    // to 64-16, so it <= 64 - 16 -1
    debug_assert!(leading_zeros <= 64 - 16 - 1, "Unexpected");
    let highest_bit = 46u32.wrapping_sub(leading_zeros); // (63-index) - (trailing 1) - (16 length of header)
    debug_assert!(highest_bit <= 46 || highest_bit == u32::MAX, "Unexpected");

    packet_handler
        .on_long_tnt_packet(context, packet_bytes, highest_bit)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_vmcs_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 7;

    let Some([byte2, byte3, byte4, byte5, byte6]) = buf
        .get((context.pos + 2)..)
        .and_then(|buf| buf.first_chunk::<5>())
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let vmcs_pointer = u64::from_le_bytes([*byte2, *byte3, *byte4, *byte5, *byte6, 0, 0, 0]) << 12;

    packet_handler
        .on_vmcs_packet(context, vmcs_pointer)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_ovf_packet<H: HandlePacket>(
    _buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    packet_handler
        .on_ovf_packet(context)
        .map_err(DecoderError::PacketHandler)?;

    context.packet_block = None;
    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_mnt_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 11;

    let Some(
        [
            byte2,
            byte3,
            byte4,
            byte5,
            byte6,
            byte7,
            byte8,
            byte9,
            byte10,
        ],
    ) = buf
        .get((context.pos + 2)..)
        .and_then(|buf| buf.first_chunk::<9>())
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    if *byte2 != 0b1000_1000 {
        return Err(DecoderError::UnexpectedEOF);
    }
    let payload = u64::from_le_bytes([
        *byte3, *byte4, *byte5, *byte6, *byte7, *byte8, *byte9, *byte10,
    ]);

    packet_handler
        .on_mnt_packet(context, payload)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_tma_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 7;

    let Some([byte2, byte3, _byte4, byte5, byte6]) = buf.get((context.pos + 2)..(context.pos + 7))
    else {
        return Err(DecoderError::UnexpectedEOF);
    };

    let ctc = u16::from_le_bytes([*byte2, *byte3]);
    let fast_counter = *byte5;
    let fc8 = *byte6 % 2 != 0;

    packet_handler
        .on_tma_packet(context, ctc, fast_counter, fc8)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

/// Payload for PTW packet
#[derive(Debug, Display, Clone, Copy)]
pub enum PtwPayload {
    /// Four bytes payload
    #[display("FourBytes({_0:#x})")]
    FourBytes(u32),
    /// Eight bytes payload
    #[display("EightBytes({_0:#x})")]
    EightBytes(u64),
}

#[inline]
fn handle_ptw_packet<H: HandlePacket>(
    buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length;

    let ip_bit = (byte & 0b1000_0000) != 0;
    let payload_bytes = (byte & 0b0110_0000) >> 5;
    debug_assert!(payload_bytes <= 0b11, "Unexpected");
    let payload = match payload_bytes {
        0b00 => {
            packet_length = 6;

            let Some(bytes) = buf
                .get((context.pos + 2)..)
                .and_then(|buf| buf.first_chunk::<4>())
            else {
                return Err(DecoderError::UnexpectedEOF);
            };
            let payload = u32::from_le_bytes(*bytes);
            PtwPayload::FourBytes(payload)
        }
        0b01 => {
            packet_length = 10;

            let Some(bytes) = buf
                .get((context.pos + 2)..)
                .and_then(|buf| buf.first_chunk::<8>())
            else {
                return Err(DecoderError::UnexpectedEOF);
            };
            let payload = u64::from_le_bytes(*bytes);
            PtwPayload::EightBytes(payload)
        }
        0b10 | 0b11 => {
            return Err(DecoderError::InvalidPacket);
        }
        _ => {
            // SAFETY: payload_bytes <= 0b11
            unsafe {
                unreachable_unchecked();
            }
        }
    };

    packet_handler
        .on_ptw_packet(context, ip_bit, payload)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_exstop_packet<H: HandlePacket>(
    _buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    let ip_bit = (byte & 0b1000_0000) != 0;

    packet_handler
        .on_exstop_packet(context, ip_bit)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_mwait_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 10;

    let Some(mwait_hints) = buf.get(context.pos + 2) else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let Some(ext) = buf.get(context.pos + 2) else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let ext = *ext & 0b0000_0011;

    packet_handler
        .on_mwait_packet(context, *mwait_hints, ext)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_pwre_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 4;

    let Some([byte2, byte3]) = buf.get((context.pos + 2)..(context.pos + 4)) else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let hw = (*byte2 & 0b1000_0000) != 0;
    let resolved_thread_c_state = (*byte3 & 0b1111_0000) >> 4;
    let resolved_thread_sub_c_state = *byte3 & 0b0000_1111;

    packet_handler
        .on_pwre_packet(
            context,
            hw,
            resolved_thread_c_state,
            resolved_thread_sub_c_state,
        )
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_pwrx_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 7;

    let Some([byte2, byte3]) = buf.get((context.pos + 2)..(context.pos + 4)) else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let last_core_c_state = (*byte2 & 0b1111_0000) >> 4;
    let deepest_core_c_state = *byte2 & 0b0000_1111;
    let wake_reason = *byte3 & 0b0000_1111;

    packet_handler
        .on_pwrx_packet(
            context,
            last_core_c_state,
            deepest_core_c_state,
            wake_reason,
        )
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_cfe_packet<H: HandlePacket>(
    buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    let ip_bit = (byte & 0b1000_0000) != 0;
    let r#type = byte & 0b0001_1111;
    let Some(vector) = buf.get(context.pos + 3) else {
        return Err(DecoderError::UnexpectedEOF);
    };

    packet_handler
        .on_cfe_packet(context, ip_bit, r#type, *vector)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_evd_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 11;

    let Some(
        [
            byte2,
            byte3,
            byte4,
            byte5,
            byte6,
            byte7,
            byte8,
            byte9,
            byte10,
        ],
    ) = buf.get((context.pos + 2)..(context.pos + 11))
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let r#type = byte2 & 0b001_1111;
    let payload = u64::from_le_bytes([
        *byte3, *byte4, *byte5, *byte6, *byte7, *byte8, *byte9, *byte10,
    ]);

    packet_handler
        .on_evd_packet(context, r#type, payload)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_bbp_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 3;

    let Some(byte) = buf.get(context.pos + 2) else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let sz_bit = (*byte & 0b1000_0000) != 0;
    let size = PacketBlockSize::from_sz_bit(sz_bit);
    let r#type = *byte & 0b0001_1111;
    packet_handler
        .on_bbp_packet(context, sz_bit, r#type)
        .map_err(DecoderError::PacketHandler)?;

    context.packet_block = Some(PacketBlockInformation { size, r#type });
    context.pos += packet_length;

    Ok(())
}

#[inline]
fn handle_bep_packet<H: HandlePacket>(
    _buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    let ip_bit = (byte & 0b1000_0000) != 0;
    packet_handler
        .on_bep_packet(context, ip_bit)
        .map_err(DecoderError::PacketHandler)?;

    context.packet_block = None;
    context.pos += packet_length;

    Ok(())
}

#[inline]
pub fn decode<H: HandlePacket>(
    buf: &[u8],
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    // Here pos + 1 since the pos is unchanged for the first byte in LV1 decode
    let Some(byte) = buf.get(context.pos + 1) else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let byte = *byte;

    match byte {
        0b0000_0011 => {
            handle_cbr_packet(buf, byte, context, packet_handler)?;
        }
        0b0001_0010 | 0b0011_0010 | 0b0101_0010 | 0b0111_0010 | 0b1001_0010 | 0b1011_0010
        | 0b1101_0010 | 0b1111_0010 => {
            // xxx10010
            handle_ptw_packet(buf, byte, context, packet_handler)?;
        }
        0b0001_0011 => {
            handle_cfe_packet(buf, byte, context, packet_handler)?;
        }
        0b0010_0010 => {
            handle_pwre_packet(buf, byte, context, packet_handler)?;
        }
        0b0010_0011 => {
            handle_psbend_packet(buf, byte, context, packet_handler)?;
        }
        0b0011_0011 | 0b1011_0011 => {
            // x0110011
            handle_bep_packet(buf, byte, context, packet_handler)?;
        }
        0b0100_0011 => {
            handle_pip_packet(buf, byte, context, packet_handler)?;
        }
        0b0101_0011 => {
            handle_evd_packet(buf, byte, context, packet_handler)?;
        }
        0b0110_0010 | 0b1110_0010 => {
            // x1100010
            handle_exstop_packet(buf, byte, context, packet_handler)?;
        }
        0b0110_0011 => {
            handle_bbp_packet(buf, byte, context, packet_handler)?;
        }
        0b0111_0011 => {
            handle_tma_packet(buf, byte, context, packet_handler)?;
        }
        0b1000_0010 => {
            handle_psb_packet(buf, byte, context, packet_handler)?;
        }
        0b1000_0011 => {
            handle_trace_stop_packet(buf, byte, context, packet_handler)?;
        }
        0b1010_0010 => {
            handle_pwrx_packet(buf, byte, context, packet_handler)?;
        }
        0b1010_0011 => {
            handle_long_tnt_packet(buf, byte, context, packet_handler)?;
        }
        0b1100_0010 => {
            handle_mwait_packet(buf, byte, context, packet_handler)?;
        }
        0b1100_1000 => {
            handle_vmcs_packet(buf, byte, context, packet_handler)?;
        }
        0b1111_0011 => {
            handle_ovf_packet(buf, byte, context, packet_handler)?;
        }
        0b1100_0011 => {
            handle_mnt_packet(buf, byte, context, packet_handler)?;
        }
        _ => {
            return Err(DecoderError::InvalidPacket);
        }
    }

    Ok(())
}
