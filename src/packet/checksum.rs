//! rfc1071 checksum abstraction

/// Calculates rfc1071 checksum value
pub fn rfc1071_checksum(packet: &[u8], initial: u32) -> u16 {
    let length = packet.len() - 1;
    let mut sum = initial;

    let mut i = 0;
    while i < length {
        let word = (packet[i] as u32) << 8 | packet[i + 1] as u32;
        sum = sum + word;
        i = i + 2;
    }
    if packet.len()%2 == 1 {
        sum = sum + (packet[length] as u32) << 8
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    return !sum as u16;
}
