use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReaderError {
    /// IO error
    #[error("IO error")]
    Io(#[from] std::io::Error),
    /// Invalid perf.data
    #[error("Invalid perf data")]
    InvalidPerfData(#[from] linux_perf_data::Error),
    /// Unexpected edge analyzer error
    #[error("Unexpected edge analyzer error")]
    Unexpected,
}

pub(crate) type ReaderResult<T> = core::result::Result<T, ReaderError>;
