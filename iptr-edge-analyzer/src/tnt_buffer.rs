use std::num::NonZero;

pub struct TntBuffer {
    buf: u64,
    count: usize,
}

impl Default for TntBuffer {
    fn default() -> Self {
        Self { buf: 0, count: 0 }
    }
}

impl TntBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    // This function will be directly inlined with const `short_tnt_packets`
    pub fn extend_with_short_tnt(
        &mut self,
        short_tnt_packet: NonZero<u8>,
        on_buffer_full: impl FnOnce(&mut Self),
    ) -> Option<NonZero<u8>> {
        let short_tnt_packet = short_tnt_packet.get();
        let highest_bit = (6 - short_tnt_packet.leading_zeros()) as usize;
        if highest_bit == 0 {
            // Nothing to extend: 0b0000_0010
            return None;
        }
        if highest_bit + self.count < 64 {
            // Not full
            self.buf |=
                (((short_tnt_packet & (0xFF >> (7 - highest_bit))) >> 1) as u64) << self.count;
            self.count += highest_bit; // self.count will never get 64
            None
        } else {
            // With this packet, get full
            let highest_bit = 64 - self.count;
            self.buf |=
                (((short_tnt_packet & (0xFF >> (7 - highest_bit))) >> 1) as u64) << self.count;
            let remain_tnt_packet = (short_tnt_packet >> highest_bit) & 0b1111_1110;
            self.count += highest_bit;
            if highest_bit == 6 {
                None
            } else {
                debug_assert_ne!(remain_tnt_packet, 0, "Unexpected!");
                Some(unsafe { NonZero::new_unchecked(remain_tnt_packet) })
            }
        }
    }

    pub fn as_array8(&self) -> [u8; 8] {
        self.buf.to_le_bytes()
    }

    pub fn as_array4(&self) -> [u8; 4] {
        let [a0, a1, a2, a3, ..] = self.buf.to_le_bytes();
        [a0, a1, a2, a3]
    }

    pub fn as_array2(&self) -> [u8; 2] {
        let [a0, a1, ..] = self.buf.to_le_bytes();
        [a0, a1]
    }

    pub fn as_array1(&self) -> [u8; 1] {
        let [a0, ..] = self.buf.to_le_bytes();
        [a0]
    }
}
