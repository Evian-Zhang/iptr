//! This module contains serveral convenient structs
//! that implments [`HandlePacket`][crate::HandlePacket].

pub mod combined;
#[cfg(feature = "log_handler")]
pub mod log;
pub mod packet_counter;
