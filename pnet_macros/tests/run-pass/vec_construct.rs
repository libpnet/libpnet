extern crate pnet_macros;
extern crate pnet_macros_support;
use pnet_macros::packet;
use pnet_macros_support::packet::PrimitiveValues;

#[packet]
pub struct PacketWithVecConstruct {
    banana: u8,
    #[length_fn = "length_fn"]
    #[construct_with(u64, u64)]
    tomatoes: Vec<Identity>,
    #[payload]
    payload: Vec<u8>,
}

fn length_fn(_: &PacketWithVecConstructPacket) -> usize {
    48
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]
pub struct Identity(pub(crate) [u8; Identity::LEN]);

impl Identity {
    const LEN: usize = 16;

    pub fn new(b0: u64, b1: u64) -> Identity {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&b0.to_be_bytes());
        buf[8..16].copy_from_slice(&b1.to_be_bytes());
        Identity(buf)
    }
}

impl PrimitiveValues for Identity {
    type T = (u64, u64);
    fn to_primitive_values(&self) -> (u64, u64) {
        (
            u64::from_be_bytes(self.0[0..8].try_into().unwrap()),
            u64::from_be_bytes(self.0[8..16].try_into().unwrap()),
        )
    }
}

fn main() {
    let test = PacketWithVecConstruct {
        banana: 1,
        tomatoes: vec![
            Identity([2u8; 16]),
            Identity([3u8; 16]),
            Identity([4u8; 16])
        ],
        payload: vec![],
    };

    let mut buf = vec![0; PacketWithVecConstructPacket::packet_size(&test)];
    let mut packet = MutablePacketWithVecConstructPacket::new(&mut buf).unwrap();
    packet.populate(&test);
    assert_eq!(packet.get_banana(), test.banana);
    assert_eq!(packet.get_tomatoes(), test.tomatoes);
}
