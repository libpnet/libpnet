#![no_main]
extern crate libfuzzer_sys;
extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::gre::GrePacket;

#[export_name="rust_fuzzer_test_input"]
pub extern fn go(data: &[u8]) {
	if let Some(gre) = GrePacket::new(data) {
		for b in gre.get_checksum_raw().iter() {
			*b;
		}

		for b in gre.get_offset_raw().iter() {
			*b;
		}

		for b in gre.get_key_raw().iter() {
			*b;
		}


		for b in gre.get_sequence_raw().iter() {
			*b;
		}


		for b in gre.get_routing_raw().iter() {
			*b;
		}
	}
}
