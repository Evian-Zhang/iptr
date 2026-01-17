//! Utility functions for dealing with extracted values in PT packets.

use crate::IpReconstructionPattern;

/// Follow the `ip_reconstruction_pattern` to update the `last_ip`.
///
/// This function will return `true` if the `last_ip` is updated. When this function
/// returns false, it means the target of FUP or TIP is out of context, according to
/// the Intel manual.
#[expect(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::enum_glob_use
)]
pub fn reconstruct_ip_and_update_last(
    last_ip: &mut u64,
    ip_reconstruction_pattern: IpReconstructionPattern,
) -> bool {
    use IpReconstructionPattern::*;
    let ip = match ip_reconstruction_pattern {
        OutOfContext => {
            // `last_ip` is not updated
            return false;
        }
        TwoBytesWithLastIp(payload) => (*last_ip & 0xFFFF_FFFF_FFFF_0000) | (payload as u64),
        FourBytesWithLastIp(payload) => (*last_ip & 0xFFFF_FFFF_0000_0000) | (payload as u64),
        SixBytesExtended(payload) => (((payload << 16) as i64) >> 16) as u64,
        SixBytesWithLastIp(payload) => (*last_ip & 0xFFFF_0000_0000_0000) | (payload as u64),
        EightBytes(payload) => payload,
    };
    *last_ip = ip;

    true
}
