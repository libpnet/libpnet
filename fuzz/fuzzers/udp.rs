#![no_main]
extern crate libfuzzer_sys;
extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::udp::UdpPacket;

#[export_name="rust_fuzzer_test_input"]
pub extern fn go(data: &[u8]) {
	if let Some(udp) = UdpPacket::new(data) {
		for b in udp.payload().iter() {
			*b;
		}
	}
}
