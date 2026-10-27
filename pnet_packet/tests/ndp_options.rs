use pnet_packet::icmpv6::ndp::{NdpOptionPacket, RouterAdvertPacket};
use pnet_packet::{Packet, PacketSize};

#[test]
fn ndp_option_lengths_use_the_full_wire_range() {
    for length in [0u8, 1, 31, 32, 33, 255] {
        let size = if length == 0 { 2 } else { length as usize * 8 };
        let mut bytes = vec![0x5a; size];
        bytes[0] = 253;
        bytes[1] = length;
        let option = NdpOptionPacket::new(&bytes).unwrap();
        assert_eq!(option.payload().len(), size - 2);
        assert_eq!(option.packet_size(), size);
    }
}

#[test]
fn router_advertisement_preserves_large_options_and_following_options() {
    let mut bytes = vec![0; 16 + 32 * 8 + 8];
    bytes[0] = 134;
    bytes[16] = 253;
    bytes[17] = 32;
    bytes[16 + 32 * 8] = 254;
    bytes[17 + 32 * 8] = 1;

    let advertisement = RouterAdvertPacket::new(&bytes).unwrap();
    let options = advertisement.get_options();
    assert_eq!(options.len(), 2);
    assert_eq!(options[0].length, 32);
    assert_eq!(options[0].data.len(), 254);
    assert_eq!(options[1].length, 1);
    assert_eq!(options[1].data.len(), 6);
}
