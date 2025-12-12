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
    count: u32,
}

impl Default for TntBufferManager {
    fn default() -> Self {
        Self {
            buf: TntBuffer(0),
            count: 0,
        }
    }
}

/// The LSB bit in short TNT packet
const SHORT_TNT_PREFIX_BIT_COUNT: u32 = 1;
/// Our decoder has already strip the first two bytes
const LONG_TNT_PREFIX_BIT_COUNT: u32 = 0;

impl TntBufferManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// You must pass a short TNT format packet here
    #[must_use]
    pub fn extend_with_short_tnt(&mut self, short_tnt_packet: u8) -> Option<TntBuffer> {
        debug_assert!(
            short_tnt_packet.leading_zeros() <= 6,
            "There should be at least one leading one bit"
        );
        // u8::BITS - 1: largest index
        // another "- 1": upmost one indicating the end of TNT BITS
        let highest_bit = u8::BITS - 1 - 1 - short_tnt_packet.leading_zeros();
        if highest_bit == SHORT_TNT_PREFIX_BIT_COUNT - 1 {
            // Nothing to extend: 0b0000_0010
            return None;
        }
        let tnt_count = highest_bit - (SHORT_TNT_PREFIX_BIT_COUNT - 1);

        let TntBuffer(buf) = &mut self.buf;
        if tnt_count + self.count < u64::BITS {
            // Not full
            *buf &= u64::MAX.wrapping_shr(64 - self.count); // Clear the part
            *buf |= ((short_tnt_packet >> SHORT_TNT_PREFIX_BIT_COUNT) as u64) << self.count;
            self.count += tnt_count; // self.count will never get u64::BITS
            None
        } else {
            // With this packet, get full
            let this_tnt_count = u64::BITS - self.count;
            *buf &= u64::MAX.wrapping_shr(64 - self.count); // Clear the part
            *buf |= ((short_tnt_packet >> SHORT_TNT_PREFIX_BIT_COUNT) as u64) << self.count;
            let full_buf = TntBuffer(*buf);
            let remain_count = tnt_count - this_tnt_count;
            *buf =
                (short_tnt_packet.wrapping_shr(this_tnt_count + SHORT_TNT_PREFIX_BIT_COUNT)) as u64;
            self.count = remain_count;
            Some(full_buf)
        }
    }

    /// You must pass a long TNT format packet here.
    ///
    /// The first two bytes must be stripped, as done by decoder.
    /// As a result, the upmost two bytes are cleared.
    #[must_use]
    pub fn extend_with_long_tnt(&mut self, long_tnt_packet: u64) -> Option<TntBuffer> {
        debug_assert_eq!(
            long_tnt_packet >> 48,
            0,
            "Upmost two bytes are not cleared!"
        );
        debug_assert_ne!(
            long_tnt_packet.leading_zeros(),
            u64::BITS,
            "There should be at least one leading one bit"
        );

        // u64::BITS - 1: largest index
        // another "- 1": upmost one indicating the end of TNT BITS
        let highest_bit = (u64::BITS - 1 - 1).wrapping_sub(long_tnt_packet.leading_zeros());
        if highest_bit == LONG_TNT_PREFIX_BIT_COUNT.wrapping_sub(1) {
            // Nothing to extend
            return None;
        }
        let tnt_count = highest_bit.wrapping_sub(LONG_TNT_PREFIX_BIT_COUNT.wrapping_sub(1));

        let TntBuffer(buf) = &mut self.buf;
        if tnt_count + self.count < u64::BITS {
            // Not full
            *buf &= u64::MAX.wrapping_shr(64 - self.count); // Clear the part
            *buf |= (long_tnt_packet >> LONG_TNT_PREFIX_BIT_COUNT) << self.count;
            self.count += tnt_count; // self.count will never get u64::BITS
            None
        } else {
            // With this packet, get full
            let this_tnt_count = u64::BITS - self.count;
            *buf &= u64::MAX.wrapping_shr(64 - self.count); // Clear the part
            *buf |= (long_tnt_packet >> LONG_TNT_PREFIX_BIT_COUNT) << self.count;
            let full_buf = TntBuffer(*buf);
            let remain_count = tnt_count - this_tnt_count;
            *buf = long_tnt_packet.wrapping_shr(this_tnt_count + LONG_TNT_PREFIX_BIT_COUNT);
            self.count = remain_count;
            Some(full_buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl TntBufferManager {
        /// May not be full, need to check [`bit_count`][Self::bit_count]
        fn buffer(&self) -> TntBuffer {
            let TntBuffer(buf) = self.buf;
            let buf = buf & u64::MAX.wrapping_shr(u64::BITS - self.count);
            TntBuffer(buf)
        }

        /// Get bit count
        fn bit_count(&self) -> u32 {
            self.count
        }
    }

    #[test]
    fn test_buffer_extend_zero_short_tnt() {
        let mut buffer_manager = TntBufferManager::default();

        // No TNT bits in this packet
        let full_buf = buffer_manager.extend_with_short_tnt(0b0000_0010);
        assert!(full_buf.is_none());
        let TntBuffer(buf) = buffer_manager.buffer();
        assert_eq!(buf, 0b0);
        assert_eq!(buffer_manager.bit_count(), 0);
    }

    #[test]
    fn test_buffer_extend_short_tnt_from_zero() {
        let mut buffer_manager = TntBufferManager::default();

        let full_buf = buffer_manager.extend_with_short_tnt(0b0110_1010);
        assert!(full_buf.is_none());
        let TntBuffer(buf) = buffer_manager.buffer();
        assert_eq!(buf, 0b10101);
        assert_eq!(buffer_manager.bit_count(), 5);
    }

    #[test]
    fn test_buffer_extend_short_tnt_until_full() {
        let mut buffer_manager = TntBufferManager::default();

        for loop_count in 0..12 {
            // Each time will add 5 bits, after 13 times, will reach full
            let full_buf = buffer_manager.extend_with_short_tnt(0b0110_1010);
            assert!(full_buf.is_none());
            assert_eq!(buffer_manager.bit_count(), 5 * (loop_count + 1));
        }
        let full_buf = buffer_manager.extend_with_short_tnt(0b0110_1010);
        assert!(full_buf.is_some());
        if let Some(TntBuffer(full_buf)) = full_buf {
            assert_eq!(
                full_buf,
                0b0101_10101_10101_10101_10101_10101_10101_10101_10101_10101_10101_10101_10101
            );
        }
        let TntBuffer(buf) = buffer_manager.buffer();
        assert_eq!(buf, 0b1);
        assert_eq!(buffer_manager.bit_count(), 1);
    }

    #[test]
    fn test_buffer_extend_zero_long_tnt() {
        let mut buffer_manager = TntBufferManager::default();

        // No TNT bits in this packet
        let full_buf =
            buffer_manager.extend_with_long_tnt(u64::from_le_bytes([0x1, 0, 0, 0, 0, 0, 0, 0]));
        assert!(full_buf.is_none());
        let TntBuffer(buf) = buffer_manager.buffer();
        assert_eq!(buf, 0b0);
        assert_eq!(buffer_manager.bit_count(), 0);
    }

    #[test]
    fn test_buffer_extend_long_tnt_from_zero() {
        let mut buffer_manager = TntBufferManager::default();

        let full_buf = buffer_manager.extend_with_long_tnt(u64::from_le_bytes([
            0b1111_1101,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]));
        assert!(full_buf.is_none());
        let TntBuffer(buf) = buffer_manager.buffer();
        assert_eq!(buf, 0b0111_1101);
        assert_eq!(buffer_manager.bit_count(), 7);
    }

    #[test]
    fn test_buffer_extend_long_tnt_until_full() {
        let mut buffer_manager = TntBufferManager::default();

        // This will add 47 TNT bits
        let full_buf = buffer_manager.extend_with_long_tnt(u64::from_le_bytes([
            0b1111_1101,
            0b1111_1101,
            0b1111_1101,
            0b1111_1101,
            0b1111_1101,
            0b1111_1101,
            0,
            0,
        ]));
        assert!(full_buf.is_none());
        assert_eq!(buffer_manager.bit_count(), 47);
        // This will add another 47 TNT bits, remain 30 bits
        let full_buf = buffer_manager.extend_with_long_tnt(u64::from_le_bytes([
            0b1111_1101,
            0b1111_1101,
            0b1111_1101,
            0b1111_1101,
            0b1111_1101,
            0b1111_1101,
            0,
            0,
        ]));
        assert!(full_buf.is_some());
        if let Some(TntBuffer(full_buf)) = full_buf {
            assert_eq!(
                full_buf,
                0b1_1111_1101_1111_1101_111_1101_1111_1101_1111_1101_1111_1101_1111_1101_1111_1101
            );
        }
        let TntBuffer(buf) = buffer_manager.buffer();
        assert_eq!(buf, 0b111_1101_1111_1101_1111_1101_1111_110);
        assert_eq!(buffer_manager.bit_count(), 30);
    }
}
