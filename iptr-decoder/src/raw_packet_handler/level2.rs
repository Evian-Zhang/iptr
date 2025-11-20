use std::hint::unreachable_unchecked;

use derive_more::Display;

use crate::{
    DecoderContext, HandlePacket,
    error::{DecoderError, DecoderResult},
};

#[inline(always)]
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
        .on_cbr_packet(*core_bus_ratio)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
fn handle_pip_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 8;

    let Some([byte2, byte3, byte4, byte5, byte6, byte7]) =
        buf.get((context.pos + 2)..(context.pos + 8))
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let rsvd_nr = (*byte2 % 2) != 0;
    let byte2 = *byte2 & 0b11111110; // Clear lowest bit
    let cr3 = u64::from_le_bytes([byte2, *byte3, *byte4, *byte5, *byte6, *byte7, 0, 0]) << 5;

    packet_handler
        .on_pip_packet(cr3, rsvd_nr)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
fn handle_psb_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    const PSB: u128 = 0x82028202820282028202820282028202;

    let packet_length = 16;

    let Some(
        [
            byte0,
            byte1,
            byte2,
            byte3,
            byte4,
            byte5,
            byte6,
            byte7,
            byte8,
            byte9,
            byte10,
            byte11,
            byte12,
            byte13,
            byte14,
            byte15,
        ],
    ) = buf.get(context.pos..(context.pos + 16))
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let psb = u128::from_le_bytes([
        *byte0, *byte1, *byte2, *byte3, *byte4, *byte5, *byte6, *byte7, *byte8, *byte9, *byte10,
        *byte11, *byte12, *byte13, *byte14, *byte15,
    ]);
    if psb != PSB {
        return Err(DecoderError::InvalidPacket);
    }

    packet_handler
        .on_psb_packet()
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
fn handle_psbend_packet<H: HandlePacket>(
    _buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    packet_handler
        .on_psbend_packet()
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
fn handle_trace_stop_packet<H: HandlePacket>(
    _buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    packet_handler
        .on_trace_stop_packet()
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[expect(clippy::int_plus_one)]
#[inline(always)]
fn handle_long_tnt_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 8;

    let Some([byte0, byte1, byte2, byte3, byte4, byte5, byte6, byte7]) =
        buf.get(context.pos..(context.pos + 8))
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let packet = u64::from_le_bytes([
        *byte0, *byte1, *byte2, *byte3, *byte4, *byte5, *byte6, *byte7,
    ]);
    let leading_zeros = packet.leading_zeros();
    if leading_zeros == 64 - 16 {
        // There is no trailing 1
        return Err(DecoderError::InvalidPacket);
    }
    debug_assert!(leading_zeros <= 64 - 16 - 1, "Invalid long TNT packet"); // The two bytes header and Stop bit
    let highest_bit = 46u32.wrapping_sub(leading_zeros); // (63-index) - (trailing 1) - (16 length of header)
    debug_assert!(highest_bit <= 46 || highest_bit == u32::MAX, "Unexpected");
    let packet_bytes = packet >> 16;

    packet_handler
        .on_long_tnt_packet(packet_bytes, highest_bit)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
fn handle_vmcs_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 7;

    let Some([byte2, byte3, byte4, byte5, byte6]) = buf.get((context.pos + 2)..(context.pos + 7))
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let vmcs_pointer = u64::from_le_bytes([*byte2, *byte3, *byte4, *byte5, *byte6, 0, 0, 0]) << 12;

    packet_handler
        .on_vmcs_packet(vmcs_pointer)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
fn handle_ovf_packet<H: HandlePacket>(
    _buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    packet_handler
        .on_ovf_packet()
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
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
    ) = buf.get((context.pos + 2)..(context.pos + 11))
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    if *byte2 != 0b10001000 {
        return Err(DecoderError::UnexpectedEOF);
    }
    let payload = u64::from_le_bytes([
        *byte3, *byte4, *byte5, *byte6, *byte7, *byte8, *byte9, *byte10,
    ]);

    packet_handler
        .on_mnt_packet(payload)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
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
        .on_tma_packet(ctc, fast_counter, fc8)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[derive(Debug, Display)]
pub enum PtwPayload {
    #[display("FourBytes({_0:#x})")]
    FourBytes(u32),
    #[display("EightBytes({_0:#x})")]
    EightBytes(u64),
}

#[inline(always)]
fn handle_ptw_packet<H: HandlePacket>(
    buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length;

    let ip_bit = (byte & 0b10000000) != 0;
    let payload_bytes = (byte & 0b01100000) >> 5;
    debug_assert!(payload_bytes <= 0b11, "Unexpected");
    let payload = match payload_bytes {
        0b00 => {
            packet_length = 6;

            let Some([byte2, byte3, byte4, byte5]) = buf.get((context.pos + 2)..(context.pos + 6))
            else {
                return Err(DecoderError::UnexpectedEOF);
            };
            let payload = u32::from_le_bytes([*byte2, *byte3, *byte4, *byte5]);
            PtwPayload::FourBytes(payload)
        }
        0b01 => {
            packet_length = 10;

            let Some([byte2, byte3, byte4, byte5, byte6, byte7, byte8, byte9]) =
                buf.get((context.pos + 2)..(context.pos + 10))
            else {
                return Err(DecoderError::UnexpectedEOF);
            };
            let payload = u64::from_le_bytes([
                *byte2, *byte3, *byte4, *byte5, *byte6, *byte7, *byte8, *byte9,
            ]);
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
        .on_ptw_packet(ip_bit, payload)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
fn handle_exstop_packet<H: HandlePacket>(
    _buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    let ip_bit = (byte & 0b10000000) != 0;

    packet_handler
        .on_exstop_packet(ip_bit)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
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
    let ext = *ext & 0b00000011;

    packet_handler
        .on_mwait_packet(*mwait_hints, ext)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
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
    let hw = (*byte2 & 0b10000000) != 0;
    let resolved_thread_c_state = (*byte3 & 0b11110000) >> 4;
    let resolved_thread_sub_c_state = *byte3 & 0b00001111;

    packet_handler
        .on_pwre_packet(hw, resolved_thread_c_state, resolved_thread_sub_c_state)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
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
    let last_core_c_state = (*byte2 & 0b11110000) >> 4;
    let deepest_core_c_state = *byte2 & 0b00001111;
    let wake_reason = *byte3 & 0b00001111;

    packet_handler
        .on_pwrx_packet(last_core_c_state, deepest_core_c_state, wake_reason)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

#[inline(always)]
fn handle_bbp_packet<H: HandlePacket>(
    _buf: &[u8],
    _byte: u8,
    _context: &mut DecoderContext,
    _packet_handler: &mut H,
) -> DecoderResult<(), H> {
    Err(DecoderError::Unimplemented)
}

#[inline(always)]
fn handle_bep_packet<H: HandlePacket>(
    _buf: &[u8],
    _byte: u8,
    _context: &mut DecoderContext,
    _packet_handler: &mut H,
) -> DecoderResult<(), H> {
    Err(DecoderError::Unimplemented)
}

#[inline(always)]
fn handle_cfe_packet<H: HandlePacket>(
    _buf: &[u8],
    _byte: u8,
    _context: &mut DecoderContext,
    _packet_handler: &mut H,
) -> DecoderResult<(), H> {
    Err(DecoderError::Unimplemented)
}

#[inline(always)]
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
    let r#type = byte2 & 0b0011111;
    let payload = u64::from_le_bytes([
        *byte3, *byte4, *byte5, *byte6, *byte7, *byte8, *byte9, *byte10,
    ]);

    packet_handler
        .on_evd_packet(r#type, payload)
        .map_err(|err| DecoderError::PacketHandler(err))?;

    context.pos += packet_length;

    Ok(())
}

pub fn decode<H: HandlePacket>(
    buf: &[u8],
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    loop {
        let Some(byte) = buf.get(context.pos) else {
            break;
        };
        let byte = *byte;

        match byte {
            0b00000011 => {
                handle_cbr_packet(buf, byte, context, packet_handler)?;
            }
            0b00010010 | 0b00110010 | 0b01010010 | 0b01110010 | 0b10010010 | 0b10110010
            | 0b11010010 | 0b11110010 => {
                // xxx10010
                handle_ptw_packet(buf, byte, context, packet_handler)?;
            }
            0b00010011 => {
                handle_cfe_packet(buf, byte, context, packet_handler)?;
            }
            0b00100010 => {
                handle_pwre_packet(buf, byte, context, packet_handler)?;
            }
            0b00100011 => {
                handle_psbend_packet(buf, byte, context, packet_handler)?;
            }
            0b00110011 | 0b10110011 => {
                // x0110011
                handle_bep_packet(buf, byte, context, packet_handler)?;
            }
            0b01000011 => {
                handle_pip_packet(buf, byte, context, packet_handler)?;
            }
            0b01010011 => {
                handle_evd_packet(buf, byte, context, packet_handler)?;
            }
            0b01100010 | 0b11100010 => {
                // x1100010
                handle_exstop_packet(buf, byte, context, packet_handler)?;
            }
            0b01100011 => {
                handle_bbp_packet(buf, byte, context, packet_handler)?;
            }
            0b01110011 => {
                handle_tma_packet(buf, byte, context, packet_handler)?;
            }
            0b10000010 => {
                handle_psb_packet(buf, byte, context, packet_handler)?;
            }
            0b10000011 => {
                handle_trace_stop_packet(buf, byte, context, packet_handler)?;
            }
            0b10100010 => {
                handle_pwrx_packet(buf, byte, context, packet_handler)?;
            }
            0b10100011 => {
                handle_long_tnt_packet(buf, byte, context, packet_handler)?;
            }
            0b11000010 => {
                handle_mwait_packet(buf, byte, context, packet_handler)?;
            }
            0b11001000 => {
                handle_vmcs_packet(buf, byte, context, packet_handler)?;
            }
            0b11110011 => {
                handle_ovf_packet(buf, byte, context, packet_handler)?;
            }
            0b11000011 => {
                handle_mnt_packet(buf, byte, context, packet_handler)?;
            }
            _ => {
                return Err(DecoderError::InvalidPacket);
            }
        }
    }

    Ok(())
}
