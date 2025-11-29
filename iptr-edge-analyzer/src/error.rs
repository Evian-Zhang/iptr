use perfect_derive::perfect_derive;
use thiserror::Error;

use crate::HandleControlFlow;

#[derive(Error)]
#[perfect_derive(Debug)]
pub enum AnalyzerError<H: HandleControlFlow> {
    /// Control flow handler error
    #[error("Control flow handler error")]
    ControlFlowHandler(#[source] H::Error),
    /// Unexpected edge analyzer error
    #[error("Unexpected edge analyzer error")]
    Unexpected,
}

pub(crate) type AnalyzerResult<T, H> = core::result::Result<T, AnalyzerError<H>>;
