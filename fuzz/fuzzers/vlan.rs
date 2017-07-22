#![no_main]
extern crate libfuzzer_sys;
extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::vlan::VlanPacket;

#[export_name="rust_fuzzer_test_input"]
pub extern fn go(data: &[u8]) {
	if let Some(vlan) = VlanPacket::new(data) {
		for b in vlan.payload().iter() {
			*b;
		}
	}
}
