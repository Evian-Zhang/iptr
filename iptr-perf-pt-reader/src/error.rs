use thiserror::Error;

/// Perf.data reader error
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ReaderError {
    /// The `perf.data` file is invalid in format
    #[error("Invalid perf.data")]
    InvalidPerfData,
    /// Unexpected EOF
    #[error("Unexpected EOF")]
    UnexpectedEOF,
}

pub(crate) type ReaderResult<T> = core::result::Result<T, ReaderError>;
