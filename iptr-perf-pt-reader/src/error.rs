use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReaderError {
    #[error("Invalid perf.data")]
    InvalidPerfData,
    /// Unexpected EOF
    #[error("Unexpected EOF")]
    UnexpectedEOF,
    /// Unexpected edge analyzer error
    #[error("Unexpected edge analyzer error")]
    Unexpected,
}

pub(crate) type ReaderResult<T> = core::result::Result<T, ReaderError>;
