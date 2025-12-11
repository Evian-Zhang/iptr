use std::num::NonZero;

/// A full TNT bits buffer
///
/// This will only be retrieved from a [`TntBufferManager`]
#[derive(Clone, Copy)]
pub struct TntBuffer(u64);

impl TntBuffer {
    /// Take all 64 TNT bits
    pub fn as_array8(&self) -> [u8; 8] {
        let Self(buf) = self;
        buf.to_le_bytes()
    }

    /// Take first 32 TNT bits
    pub fn as_array4(&self) -> [u8; 4] {
        let Self(buf) = self;
        let [a0, a1, a2, a3, ..] = buf.to_le_bytes();
        [a0, a1, a2, a3]
    }

    /// Take first 16 TNT bits
    pub fn as_array2(&self) -> [u8; 2] {
        let Self(buf) = self;
        let [a0, a1, ..] = buf.to_le_bytes();
        [a0, a1]
    }

    /// Take first 8 TNT bits
    pub fn as_array1(&self) -> [u8; 1] {
        let Self(buf) = self;
        let [a0, ..] = buf.to_le_bytes();
        [a0]
    }
}

pub struct TntBufferManager {
    buf: TntBuffer,
    count: usize,
}

impl Default for TntBufferManager {
    fn default() -> Self {
        Self {
            buf: TntBuffer(0),
            count: 0,
        }
    }
}

impl TntBufferManager {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn extend_with_short_tnt(&mut self, short_tnt_packet: u8) -> Option<TntBuffer> {
        let highest_bit = (6 - short_tnt_packet.leading_zeros()) as usize;
        if highest_bit == 0 {
            // Nothing to extend: 0b0000_0010
            return None;
        }
        let TntBuffer(buf) = &mut self.buf;
        if highest_bit + self.count < 64 {
            // Not full
            *buf |= (((short_tnt_packet & (0xFF >> (7 - highest_bit))) >> 1) as u64) << self.count;
            self.count += highest_bit; // self.count will never get 64
            None
        } else {
            // With this packet, get full
            let this_highest_bit = 64 - self.count;
            *buf |=
                (((short_tnt_packet & (0xFF >> (7 - this_highest_bit))) >> 1) as u64) << self.count;
            let full_buf = TntBuffer(*buf);
            let remain_count = highest_bit - this_highest_bit;
            *buf = ((short_tnt_packet >> (this_highest_bit + 1)) & (0xFF >> (8 - (remain_count))))
                as u64;
            self.count = remain_count;
            Some(full_buf)
        }
    }

    /// May not be full, need to check [`bit_count`][Self::bit_count]
    pub fn buffer(&self) -> TntBuffer {
        self.buf
    }

    pub fn bit_count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_extend_from_zero() {
        let mut buffer_manager = TntBufferManager::default();

        let full_buf = buffer_manager.extend_with_short_tnt(0b01101010);
        assert!(full_buf.is_none());
        let TntBuffer(buf) = buffer_manager.buf;
        assert_eq!(buf, 0b10101);
        assert_eq!(buffer_manager.bit_count(), 5);
    }

    #[test]
    fn test_buffer_extend_until_full() {
        let mut buffer_manager = TntBufferManager::default();

        for loop_count in 0..12 {
            // Each time will add 5 bits, after 13 times, will reach full
            let full_buf = buffer_manager.extend_with_short_tnt(0b01101010);
            assert!(full_buf.is_none());
            assert_eq!(buffer_manager.bit_count(), 5 * (loop_count + 1));
        }
        let full_buf = buffer_manager.extend_with_short_tnt(0b01101010);
        assert!(full_buf.is_some());
        if let Some(TntBuffer(full_buf)) = full_buf {
            assert_eq!(
                full_buf,
                0b0101_10101_10101_10101_10101_10101_10101_10101_10101_10101_10101_10101_10101
            );
        }
        let TntBuffer(buf) = buffer_manager.buf;
        assert_eq!(buf, 0b1);
        assert_eq!(buffer_manager.bit_count(), 1);
    }
}
