pub mod error;

use std::marker::PhantomData;

use error::Result;

pub trait HandlePacket {}

struct RawPacketHandlers<H: HandlePacket> {
    phantom: PhantomData<H>,
}

impl<H: HandlePacket> RawPacketHandlers<H> {
    const HANDLERS: [RawPacketHandler<H>; 256] = const {
        let mut handlers: [RawPacketHandler<H>; 256] = [handle_pad_packet::<H>; 256];

        let mut index = 0;

        loop {
            if index >= 256 {
                break;
            }
            let cur_index = index;
            index += 1;

            let handler = if cur_index == 0b00000000 {
                // 00000000
                handle_pad_packet::<H>
            } else if cur_index & 0b00011111 == 0b00000001 {
                // xxx00001
                handle_tip_pgd_packet::<H>
            } else if cur_index == 0b00000010 {
                // 00000010
                handle_level2_packet::<H>
            } else if cur_index & 0b00000011 == 0b00000011 {
                // xxxxxx11
                handle_cyc_packet::<H>
            } else if cur_index & 0b00000001 == 0b00000000 {
                // xxxxxxx0 but not 00000000 and 00000010
                handle_short_tnt_packet::<H>
            } else if cur_index & 0b00011111 == 0b00001101 {
                // xxx01101
                handle_tip_packet::<H>
            } else if cur_index & 0b00011111 == 0b00010001 {
                // xxx10001
                handle_tip_pge_packet::<H>
            } else if cur_index == 0b00011001 {
                // 00011001
                handle_tsc_packet::<H>
            } else if cur_index & 0b00011111 == 0b00011101 {
                // xxx11101
                handle_fup_packet::<H>
            } else if cur_index == 0b01011001 {
                // 01011001
                handle_mtc_packet::<H>
            } else if cur_index == 0b10011001 {
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

type RawPacketHandler<H> = fn(buf: &[u8], pos: &mut usize, packet_handler: &mut H) -> Result<()>;

fn handle_pad_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_tip_pgd_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_tip_pge_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_level2_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_cyc_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_short_tnt_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_tip_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_tsc_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_fup_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_mtc_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_mode_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}
fn handle_wrong_packet<H: HandlePacket>(
    buf: &[u8],
    pos: &mut usize,
    handle_packet: &mut H,
) -> Result<()> {
    Ok(())
}

pub fn decode<H: HandlePacket>(buf: &[u8], packet_handler: &mut H) {
    let mut pos = 0;
    loop {
        let Some(byte) = buf.get(pos) else {
            break;
        };
        let _ = RawPacketHandlers::<H>::HANDLERS[*byte as usize](buf, &mut pos, packet_handler);
    }
}
