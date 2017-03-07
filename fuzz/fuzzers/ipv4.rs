#![no_main]
extern crate libfuzzer_sys;
extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;

#[export_name="rust_fuzzer_test_input"]
pub extern fn go(data: &[u8]) {
	if let Some(ipv4) = Ipv4Packet::new(data) {
		let options = ipv4.get_options_raw();
		for o in options.iter() {
			*o;
		}
		for b in ipv4.payload().iter() {
			*b;
		}
	}
}
