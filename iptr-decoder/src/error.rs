use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecoderError {
    #[error("Unexpected decoder error")]
    Unexpected,
}

pub(crate) type Result<T> = std::result::Result<T, DecoderError>;
