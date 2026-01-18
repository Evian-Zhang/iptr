#[cfg(feature = "libxdc_memory_reader")]
pub mod libxdc;
#[cfg(feature = "perf_memory_reader")]
pub mod perf_mmap;

/// Memory reader
pub trait ReadMemory {
    /// Error for memory reading
    type Error: std::error::Error;

    /// Callback at begin of decoding.
    ///
    /// This is useful when using the same handler to process multiple Intel PT
    /// traces
    fn at_decode_begin(&mut self) -> Result<(), Self::Error>;

    /// Read memories at given address with given size, and
    /// invoke the given callback with the read memories.
    ///
    /// This function is allowed to read memories shorter than
    /// `size`.
    ///
    /// This function will return the callback return value on success.
    fn read_memory<T>(
        &mut self,
        address: u64,
        size: usize,
        callback: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, Self::Error>;
}
