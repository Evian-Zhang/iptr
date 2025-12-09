use core::hint::unreachable_unchecked;

use derive_more::Display;

use crate::{
    DecoderContext, HandlePacket, TraceeMode,
    error::{DecoderError, DecoderResult},
    raw_packet_handler::{RawPacketHandler, RawPacketHandlers},
};

impl<H: HandlePacket> RawPacketHandlers<H> {
    const LEVEL1_HANDLERS: [RawPacketHandler<H>; 256] = const {
        let mut handlers: [RawPacketHandler<H>; 256] = [handle_wrong_packet::<H>; 256];

        let mut index = 0;

        loop {
            if index >= 256 {
                break;
            }
            let cur_index = index;
            index += 1;

            let handler = if cur_index == 0b0000_0000 {
                // 00000000
                handle_pad_packet::<H>
            } else if cur_index & 0b0001_1111 == 0b0000_0001 {
                // xxx00001
                handle_tip_pgd_packet::<H>
            } else if cur_index == 0b0000_0010 {
                // 00000010
                handle_level2_packet::<H>
            } else if cur_index & 0b0000_0011 == 0b0000_0011 {
                // xxxxxx11
                handle_cyc_packet::<H>
            } else if cur_index & 0b0000_0001 == 0b0000_0000 {
                // xxxxxxx0 but not 00000000 and 00000010
                handle_short_tnt_packet::<H>
            } else if cur_index & 0b0001_1111 == 0b0000_1101 {
                // xxx01101
                handle_tip_packet::<H>
            } else if cur_index & 0b0001_1111 == 0b0001_0001 {
                // xxx10001
                handle_tip_pge_packet::<H>
            } else if cur_index == 0b0001_1001 {
                // 00011001
                handle_tsc_packet::<H>
            } else if cur_index & 0b0001_1111 == 0b0001_1101 {
                // xxx11101
                handle_fup_packet::<H>
            } else if cur_index == 0b0101_1001 {
                // 01011001
                handle_mtc_packet::<H>
            } else if cur_index == 0b1001_1001 {
                // 10011001
                handle_mode_packet::<H>
            } else {
                // Anything else
                handle_wrong_packet::<H>
            };

            handlers[cur_index] = handler;
        }

        handlers
    };
}

fn handle_pad_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 1;

    loop {
        packet_handler
            .on_pad_packet(context)
            .map_err(DecoderError::PacketHandler)?;

        context.pos += packet_length;
        let Some(byte) = buf.get(context.pos) else {
            break;
        };
        if *byte != 0b0000_0000 {
            break;
        }
        // Fast path for continuous PAD packet
    }

    Ok(())
}

fn handle_short_tnt_packet<H: HandlePacket>(
    _buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    // The short TNT packets always ends with 0, so leading zeros will never be 7;
    // The 0b00000000 is PAD packet, so leading zeros will never be 8, so no need
    // to check the trailing 1
    debug_assert!(byte.leading_zeros() <= 6, "Unexpected short TNT packet!");

    let packet_length = 1;

    let highest_bit = 6 - byte.leading_zeros();
    packet_handler
        .on_short_tnt_packet(context, byte, highest_bit)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

fn handle_tip_packet<H: HandlePacket>(
    buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    context.pos += 1; // Header

    let ip_bytes = byte >> 5;
    // SAFETY: ip_bytes is not greater than 0b111
    let ip_reconstruction_pattern = unsafe { ip_reconstruction(buf, ip_bytes, context)? };

    packet_handler
        .on_tip_packet(context, ip_reconstruction_pattern)
        .map_err(DecoderError::PacketHandler)?;

    Ok(())
}

fn handle_tip_pgd_packet<H: HandlePacket>(
    buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    context.pos += 1; // Header

    let ip_bytes = byte >> 5;
    // SAFETY: ip_bytes is not greater than 0b111
    let ip_reconstruction_pattern = unsafe { ip_reconstruction(buf, ip_bytes, context)? };

    packet_handler
        .on_tip_pgd_packet(context, ip_reconstruction_pattern)
        .map_err(DecoderError::PacketHandler)?;

    Ok(())
}

fn handle_tip_pge_packet<H: HandlePacket>(
    buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    context.pos += 1; // Header

    let ip_bytes = byte >> 5;
    // SAFETY: ip_bytes is not greater than 0b111
    let ip_reconstruction_pattern = unsafe { ip_reconstruction(buf, ip_bytes, context)? };

    packet_handler
        .on_tip_pge_packet(context, ip_reconstruction_pattern)
        .map_err(DecoderError::PacketHandler)?;

    Ok(())
}

fn handle_fup_packet<H: HandlePacket>(
    buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    context.pos += 1; // Header

    let ip_bytes = byte >> 5;
    // SAFETY: ip_bytes is not greater than 0b111
    let ip_reconstruction_pattern = unsafe { ip_reconstruction(buf, ip_bytes, context)? };

    packet_handler
        .on_fup_packet(context, ip_reconstruction_pattern)
        .map_err(DecoderError::PacketHandler)?;

    Ok(())
}

/// Pattern for IP reconstruction
#[derive(Debug, Display, Clone, Copy)]
pub enum IpReconstructionPattern {
    /// None, IP is out of context
    OutOfContext,
    /// IP Payload[15:0]
    #[display("TwoBytesWithLastIp({_0:#x})")]
    TwoBytesWithLastIp(u16),
    /// IP Payload[31:0]
    #[display("FourBytesWithLastIp({_0:#x})")]
    FourBytesWithLastIp(u32),
    /// IP Payload[47:0], the upper 2 bytes are guaranteed to be cleared
    #[display("SixBytesExtended({_0:#x})")]
    SixBytesExtended(u64),
    /// IP Payload[47:0], the upper 2 bytes are guaranteed to be cleared
    #[display("SixBytesWithLastIp({_0:#x})")]
    SixBytesWithLastIp(u64),
    /// IP Payload[63:0]
    #[display("EightBytes({_0:#x})")]
    EightBytes(u64),
}

/// pos should be updated by 1 (header) before calling the function
///
/// # SAFETY
///
/// `ip_bytes` should be no greater than 0b111
#[expect(clippy::manual_range_patterns)]
unsafe fn ip_reconstruction<H: HandlePacket>(
    buf: &[u8],
    ip_bytes: u8,
    context: &mut DecoderContext,
) -> DecoderResult<IpReconstructionPattern, H> {
    debug_assert!(ip_bytes <= 0b111, "Unexpected ip bytes.");
    let pattern = match ip_bytes {
        // Header only, no IP payload
        0b000 => IpReconstructionPattern::OutOfContext,
        0b001 => {
            let Some(bytes) = buf
                .get(context.pos..)
                .and_then(|buf| buf.first_chunk::<2>())
            else {
                return Err(DecoderError::UnexpectedEOF);
            };
            let ip_payload = u16::from_le_bytes(*bytes);

            context.pos += 2;

            IpReconstructionPattern::TwoBytesWithLastIp(ip_payload)
        }
        0b010 => {
            let Some(bytes) = buf
                .get(context.pos..)
                .and_then(|buf| buf.first_chunk::<4>())
            else {
                return Err(DecoderError::UnexpectedEOF);
            };
            let ip_payload = u32::from_le_bytes(*bytes);

            context.pos += 4;

            IpReconstructionPattern::FourBytesWithLastIp(ip_payload)
        }
        0b011 if matches!(context.tracee_mode, TraceeMode::Mode64) => {
            let Some([byte1, byte2, byte3, byte4, byte5, byte6]) = buf
                .get(context.pos..)
                .and_then(|buf| buf.first_chunk::<6>())
            else {
                return Err(DecoderError::UnexpectedEOF);
            };
            let ip_payload =
                u64::from_le_bytes([*byte1, *byte2, *byte3, *byte4, *byte5, *byte6, 0, 0]);

            context.pos += 6;

            IpReconstructionPattern::SixBytesExtended(ip_payload)
        }
        0b100 if matches!(context.tracee_mode, TraceeMode::Mode64) => {
            let Some([byte1, byte2, byte3, byte4, byte5, byte6]) = buf
                .get(context.pos..)
                .and_then(|buf| buf.first_chunk::<6>())
            else {
                return Err(DecoderError::UnexpectedEOF);
            };
            let ip_payload =
                u64::from_le_bytes([*byte1, *byte2, *byte3, *byte4, *byte5, *byte6, 0, 0]);

            context.pos += 6;

            IpReconstructionPattern::SixBytesWithLastIp(ip_payload)
        }
        0b110 if matches!(context.tracee_mode, TraceeMode::Mode64) => {
            let Some(bytes) = buf
                .get(context.pos..)
                .and_then(|buf| buf.first_chunk::<8>())
            else {
                return Err(DecoderError::UnexpectedEOF);
            };
            let ip_payload = u64::from_le_bytes(*bytes);

            context.pos += 8;

            IpReconstructionPattern::EightBytes(ip_payload)
        }
        0b011 | 0b100 | 0b101 | 0b110 | 0b111 => {
            return Err(DecoderError::InvalidPacket);
        }
        _ => {
            // SAFETY: ip_bytes should be no greater than than 0b111
            unsafe {
                unreachable_unchecked();
            }
        }
    };

    Ok(pattern)
}

fn handle_cyc_packet<H: HandlePacket>(
    buf: &[u8],
    byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let mut exp = (byte & 0b0000_0100) != 0;
    let mut end_pos = context.pos + 1;

    loop {
        if !exp {
            break;
        }
        let Some(byte) = buf.get(end_pos) else {
            return Err(DecoderError::UnexpectedEOF);
        };
        exp = byte % 2 != 0;
        end_pos += 1;
    }

    // SAFETY: All bytes are accessed before.
    debug_assert!(buf.len() > end_pos, "Unexpected");
    packet_handler
        .on_cyc_packet(context, unsafe { buf.get_unchecked(context.pos..end_pos) })
        .map_err(DecoderError::PacketHandler)?;

    context.pos = end_pos;

    Ok(())
}

fn handle_tsc_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 8;

    let Some([byte1, byte2, byte3, byte4, byte5, byte6, byte7]) = buf
        .get((context.pos + 1)..)
        .and_then(|buf| buf.first_chunk::<7>())
    else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let tsc_bytes = [*byte1, *byte2, *byte3, *byte4, *byte5, *byte6, *byte7, 0];
    let tsc_value = u64::from_le_bytes(tsc_bytes);

    packet_handler
        .on_tsc_packet(context, tsc_value)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

fn handle_mtc_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    let Some(byte) = buf.get(context.pos + 1) else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let ctc_payload = *byte;

    packet_handler
        .on_mtc_packet(context, ctc_payload)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

fn handle_mode_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    let packet_length = 2;

    let Some(byte) = buf.get(context.pos + 1) else {
        return Err(DecoderError::UnexpectedEOF);
    };
    let byte = *byte;
    let leaf_id = (byte & 0b1110_0000) >> 5;
    let mode = byte & 0b0001_1111;

    if leaf_id == 0b000 {
        // MODE.exec packet
        match mode & 0b0000_0011 {
            0b00 => context.tracee_mode = TraceeMode::Mode16,
            0b01 => context.tracee_mode = TraceeMode::Mode64,
            0b10 => context.tracee_mode = TraceeMode::Mode32,
            _ => {}
        }
    }

    packet_handler
        .on_mode_packet(context, leaf_id, mode)
        .map_err(DecoderError::PacketHandler)?;

    context.pos += packet_length;

    Ok(())
}

fn handle_wrong_packet<H: HandlePacket>(
    _buf: &[u8],
    _byte: u8,
    _context: &mut DecoderContext,
    _packet_handler: &mut H,
) -> DecoderResult<(), H> {
    Err(DecoderError::InvalidPacket)
}

fn handle_level2_packet<H: HandlePacket>(
    buf: &[u8],
    _byte: u8,
    context: &mut DecoderContext,
    packet_handler: &mut H,
) -> DecoderResult<(), H> {
    // All pos should be updated by level2's decode
    super::level2::decode(buf, context, packet_handler)?;

    Ok(())
}

macro_rules! h {
    ($byte: ident, $buf: ident, $context: ident, $packet_handler: ident : $($val:literal),*) => {
        match $byte {
            $(
                $val => RawPacketHandlers::<H>::LEVEL1_HANDLERS[$val]($buf, $byte, $context, $packet_handler),
            )*
        }
    };
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
        // Note that context.pos has not been updated before calling dispatch functions
        h!(byte, buf, context, packet_handler: 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255)?;
    }

    Ok(())
}
