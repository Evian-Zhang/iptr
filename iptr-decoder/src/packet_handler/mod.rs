//! This module contains serveral convenient structs
//! that implments [`HandlePacket`][crate::HandlePacket].

pub mod combined;
#[cfg(feature = "alloc")]
pub mod log;
pub mod packet_counter;
