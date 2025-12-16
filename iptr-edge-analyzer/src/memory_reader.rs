/// Memory reader
pub trait ReadMemory {
    /// Error for memory reading
    type Error: std::error::Error;

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
