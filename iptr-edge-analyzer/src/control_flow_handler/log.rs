//! Control flow handler that logs.

use crate::HandleControlFlow;

/// Control flow handler that logs every basic block information.
#[derive(Default)]
pub struct LogControlFlowHandler {}

impl HandleControlFlow for LogControlFlowHandler {
    // Log does not produce high-level errors
    type Error = std::convert::Infallible;

    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn on_new_block(
        &mut self,
        block_addr: u64,
        transition_kind: super::ControlFlowTransitionKind,
        _cache: bool,
    ) -> Result<(), Self::Error> {
        log::trace!("Block {block_addr:#x} encountered via {transition_kind}");
        Ok(())
    }
}
