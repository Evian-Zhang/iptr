pub trait ReadMemory {
    type Error: std::error::Error;

    fn read_memory<T>(
        &mut self,
        address: u64,
        size: usize,
        callback: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, Self::Error>;
}
