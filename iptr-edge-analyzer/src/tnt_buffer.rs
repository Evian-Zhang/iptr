//! TNT buffer structure

use crate::{
    HandleControlFlow, ReadMemory,
    error::{AnalyzerError, AnalyzerResult},
};

/// A buffer for TNT bits
///
/// This will only be retrieved from a [`TntBufferManager`]
#[derive(Clone, Copy)]
pub struct TntBuffer {
    /// 64 bits container
    value: u64,
    /// Number of used bits, no more than [`u64::BITS`].
    bits: u32,
}

impl TntBuffer {
    /// Take all 64 TNT bits
    pub fn get_array_qword(&self) -> [u8; 8] {
        self.value.to_le_bytes()
    }

    /// Get current bits count. The bits count will not be greater than [`u64::BITS`].
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Remove the first n bits, equivalent to logical shift right.
    ///
    /// # Examples
    ///
    /// ```rust, ignore
    /// # let buf = TntBuffer { value: 0b0001_1001, bits: 5 };
    /// // let buf = ...
    /// assert_eq!(buf.to_array_qword(), [0b0001_1001, 0, 0, 0, 0, 0, 0, 0]);
    /// assert_eq!(buf.bits(), 5);
    /// let new_buf = buf.remove_first_n_bits(2);
    /// assert_eq!(buf.to_array_qword(), [0b0000_0110, 0, 0, 0, 0, 0, 0, 0]);
    /// assert_eq!(buf.bits(), 3);
    /// ```
    pub fn remove_first_n_bits(self, n: u32) -> Self {
        let mut this = self;
        this.value = this.value.wrapping_shr(n);
        this.bits = this.bits.saturating_sub(n);

        this
    }

    /// Clear unoccupied bits to avoid confusion.
    ///
    /// Always call this function before returning a non-full [`TntBuffer`]
    /// in public functions
    fn ready_for_public_usage(mut self) -> Self {
        self.value &= u64::MAX.wrapping_shr(u64::BITS - self.bits);
        self
    }
}

/// Manager for TNT buffers
pub struct TntBufferManager {
    /// The internal buffer
    buf: TntBuffer,
}

impl Default for TntBufferManager {
    fn default() -> Self {
        Self {
            buf: TntBuffer { value: 0, bits: 0 },
        }
    }
}

/// The LSB bit in short TNT packet
const SHORT_TNT_PREFIX_BIT_COUNT: u32 = 1;
/// Our decoder has already strip the first two bytes
const LONG_TNT_PREFIX_BIT_COUNT: u32 = 0;

impl TntBufferManager {
    /// Create a new TNT buffer manager
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear current TNT buffer
    pub fn clear(&mut self) {
        self.buf.value = 0;
        self.buf.bits = 0;
    }

    /// Insert TNT bits in a short TNT packet into the TNT buffer.
    ///
    /// This function will return a full 64-bits TNT buffer if current buffer
    /// is full after the insertion
    ///
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

        if tnt_count + self.buf.bits < u64::BITS {
            // Not full
            self.buf.value &= u64::MAX.wrapping_shr(64 - self.buf.bits); // Clear the part
            self.buf.value |=
                ((short_tnt_packet >> SHORT_TNT_PREFIX_BIT_COUNT) as u64) << self.buf.bits;
            self.buf.bits += tnt_count; // self.buf.bits will never get u64::BITS
            None
        } else {
            // With this packet, get full
            // The buf may already been full, then this will still function normally
            let this_tnt_count = u64::BITS - self.buf.bits;
            self.buf.value &= u64::MAX.wrapping_shr(64 - self.buf.bits); // Clear the part
            self.buf.value |= ((short_tnt_packet >> SHORT_TNT_PREFIX_BIT_COUNT) as u64)
                .wrapping_shl(self.buf.bits);
            let full_buf = TntBuffer {
                value: self.buf.value,
                bits: u64::BITS,
            };
            let remain_count = tnt_count - this_tnt_count;
            self.buf.value =
                (short_tnt_packet.wrapping_shr(this_tnt_count + SHORT_TNT_PREFIX_BIT_COUNT)) as u64;
            self.buf.bits = remain_count;
            Some(full_buf)
        }
    }

    /// Insert TNT bits in a long TNT packet into the TNT buffer.
    ///
    /// This function will return a full 64-bits TNT buffer if current buffer
    /// is full after the insertion
    ///
    /// You must pass a long TNT format packet here. The first two bytes must be stripped,
    /// as done by decoder. As a result, the upmost two bytes of `long_tnt_packet` are cleared.
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

        if tnt_count + self.buf.bits < u64::BITS {
            // Not full
            self.buf.value &= u64::MAX.wrapping_shr(64 - self.buf.bits); // Clear the part
            self.buf.value |= (long_tnt_packet >> LONG_TNT_PREFIX_BIT_COUNT) << self.buf.bits;
            self.buf.bits += tnt_count; // self.buf.bits will never get u64::BITS
            None
        } else {
            // With this packet, get full
            // The buf may already been full, then this will still function normally
            let this_tnt_count = u64::BITS - self.buf.bits;
            self.buf.value &= u64::MAX.wrapping_shr(64 - self.buf.bits); // Clear the part
            self.buf.value |=
                (long_tnt_packet >> LONG_TNT_PREFIX_BIT_COUNT).wrapping_shl(self.buf.bits);
            let full_buf = TntBuffer {
                value: self.buf.value,
                bits: u64::BITS,
            };
            let remain_count = tnt_count - this_tnt_count;
            self.buf.value =
                long_tnt_packet.wrapping_shr(this_tnt_count + LONG_TNT_PREFIX_BIT_COUNT);
            self.buf.bits = remain_count;
            Some(full_buf)
        }
    }

    /// Prepend given buf to the internal TNT buffer.
    ///
    /// This function will return error if the TNT buffer exceeded.
    pub fn prepend_buf<H: HandleControlFlow, R: ReadMemory>(
        &mut self,
        buf: TntBuffer,
    ) -> AnalyzerResult<(), H, R> {
        if self.buf.bits() + buf.bits() > u64::BITS {
            return Err(AnalyzerError::ExceededTntBuffer);
        }
        self.buf.value = self.buf.value.wrapping_shl(buf.bits());
        self.buf.value |= buf.value & (u64::MAX.wrapping_shr(u64::BITS - buf.bits()));
        self.buf.bits += buf.bits();

        Ok(())
    }

    /// Take current tnt buffer out of the manager, leaving
    /// a new buffer in place.
    pub fn take(&mut self) -> TntBuffer {
        let buf = self.buf;
        self.clear();
        buf.ready_for_public_usage()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl TntBufferManager {
        /// May not be full
        fn buffer(&self) -> TntBuffer {
            let buffer = self.buf;
            buffer.ready_for_public_usage()
        }
    }

    #[test]
    fn test_buffer_extend_zero_short_tnt() {
        let mut buffer_manager = TntBufferManager::default();

        // No TNT bits in this packet
        let full_buf = buffer_manager.extend_with_short_tnt(0b0000_0010);
        assert!(full_buf.is_none());
        let buf = buffer_manager.buffer();
        assert_eq!(buf.value, 0b0);
        assert_eq!(buf.bits, 0);
    }

    #[test]
    fn test_buffer_extend_short_tnt_from_zero() {
        let mut buffer_manager = TntBufferManager::default();

        let full_buf = buffer_manager.extend_with_short_tnt(0b0110_1010);
        assert!(full_buf.is_none());
        let buf = buffer_manager.buffer();
        assert_eq!(buf.value, 0b10101);
        assert_eq!(buf.bits, 5);
    }

    #[test]
    fn test_buffer_extend_short_tnt_until_full() {
        let mut buffer_manager = TntBufferManager::default();

        for loop_count in 0..12 {
            // Each time will add 5 bits, after 13 times, will reach full
            let full_buf = buffer_manager.extend_with_short_tnt(0b0110_1010);
            assert!(full_buf.is_none());
            assert_eq!(buffer_manager.buffer().bits, 5 * (loop_count + 1));
        }
        let full_buf = buffer_manager.extend_with_short_tnt(0b0110_1010);
        assert!(full_buf.is_some());
        if let Some(full_buf) = full_buf {
            assert_eq!(
                full_buf.value,
                0b0101_10101_10101_10101_10101_10101_10101_10101_10101_10101_10101_10101_10101
            );
            assert_eq!(full_buf.bits, u64::BITS);
        }
        let buf = buffer_manager.buffer();
        assert_eq!(buf.value, 0b1);
        assert_eq!(buf.bits, 1);
    }

    #[test]
    fn test_buffer_extend_zero_long_tnt() {
        let mut buffer_manager = TntBufferManager::default();

        // No TNT bits in this packet
        let full_buf =
            buffer_manager.extend_with_long_tnt(u64::from_le_bytes([0x1, 0, 0, 0, 0, 0, 0, 0]));
        assert!(full_buf.is_none());
        let buf = buffer_manager.buffer();
        assert_eq!(buf.value, 0b0);
        assert_eq!(buf.bits, 0);
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
        let buf = buffer_manager.buffer();
        assert_eq!(buf.value, 0b0111_1101);
        assert_eq!(buf.bits, 7);
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
        assert_eq!(buffer_manager.buffer().bits, 47);
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
        if let Some(full_buf) = full_buf {
            assert_eq!(
                full_buf.value,
                0b1_1111_1101_1111_1101_111_1101_1111_1101_1111_1101_1111_1101_1111_1101_1111_1101
            );
            assert_eq!(full_buf.bits, u64::BITS);
        }
        let buf = buffer_manager.buffer();
        assert_eq!(buf.value, 0b111_1101_1111_1101_1111_1101_1111_110);
        assert_eq!(buf.bits, 30);
    }
}
