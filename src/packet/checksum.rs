//! rfc1071 checksum abstraction

/// Calculates rfc1071 checksum value
pub fn rfc1071_checksum(packet: &[u8], initial: u32) -> u16 {
    let len = packet.len();
    let mut i = 0;
    let mut sum = initial;
    while i < len {
        let word = (packet[i] as u32) << 8 | packet[i + 1] as u32;
        sum = sum + word;
        i = i + 2;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    return !sum as u16;
}
