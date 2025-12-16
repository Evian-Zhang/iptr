//! This module contains definition of errors made when analyzing with [`EdgeAnalyzer`][crate::EdgeAnalyzer].
//!
use perfect_derive::perfect_derive;
use thiserror::Error;

use crate::{HandleControlFlow, ReadMemory};

/// Error for edge analysis
#[derive(Error)]
#[perfect_derive(Debug)]
pub enum AnalyzerError<H: HandleControlFlow, R: ReadMemory> {
    /// Control flow handler error
    #[error("Control flow handler error")]
    ControlFlowHandler(#[source] H::Error),
    /// Memory reader error
    #[error("Memory reader error")]
    MemoryReader(#[source] R::Error),
    /// Instructions non-decodable by iced-x86
    #[error("Invalid instruction: {}", .0.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" "))]
    InvalidInstruction(Box<[u8]>),
    /// Corrupted callstack, will affect the behavior
    /// of return compression
    #[error("The self-maintained callstack is corrupted")]
    CorruptedCallstack,
    /// Semantic-level invalid packet
    #[error("Invalid packet")]
    InvalidPacket,
    /// Return compression is not supported since we need to maintain
    /// the callstack in the cache, which is very hard to design a efficient way
    #[error("Return compression is not supported")]
    UnsupportedReturnCompression,
    /// Unexpected edge analyzer error
    #[error("Unexpected edge analyzer error")]
    Unexpected,
}

pub(crate) type AnalyzerResult<T, H, R> = core::result::Result<T, AnalyzerError<H, R>>;
