
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv6;


#[test]
fn main() {
    let id = 3;
    let fragment_offset = 0;
    let mf = 1;

    let payload = [0, 1, 2, 3];
    let payload_len = payload.len();
    println!(
        "main: payload_len: {}",
        payload_len
    );

    let ipv6fragment_extension_header_header_len = 8;
    let ipv6_fragment_exetension_header_packet_len = ipv6fragment_extension_header_header_len + payload_len;
    println!(
        "main: ipv6_fragment_exetension_header_packet_len: {}",
        ipv6_fragment_exetension_header_packet_len
    );

    // We shift fragment_offset 3 bits to the left and add the MF bit from fragment_flag (last bit).
    let fragment_offset_with_flags = fragment_offset * 8 + mf;

    let mut fragment_data_like_v: Vec<u8> = vec![0; ipv6_fragment_exetension_header_packet_len];
    let fragment = ipv6::Fragment {
        next_header: IpNextHeaderProtocol::new(0),
        reserved: 0,
        fragment_offset_with_flags,
        id: id as u32,
        payload: payload.to_vec(),
    };
    let mut mutable_fragment_packet = ipv6::MutableFragmentPacket::new(&mut fragment_data_like_v[..]).unwrap();
    mutable_fragment_packet.populate(&fragment);

    println!(
        "main: data: {:?}",
        mutable_fragment_packet.packet().to_vec()
    );

    assert_eq!(payload, mutable_fragment_packet.payload());

    println!("main: done - Payload: {:?}", mutable_fragment_packet.payload());
}
