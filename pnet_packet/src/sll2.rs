use alloc::vec::Vec;

use pnet_macros::packet;
use pnet_macros_support::types::*;

use super::ethernet::EtherType;

#[packet]
pub struct SLL2 {
    #[construct_with(u16)]
    protocol: EtherType,
    
    #[construct_with(u32)]
    interface_index: u32be,
    
    #[construct_with(u16)]
    ha_type: u16be,
    
    #[construct_with(u8)]
    packet_type: u8,
    
    #[construct_with(u8)]
    link_layer_address_length: u8,
    
    #[construct_with(u8, u8, u8, u8, u8, u8, u8, u8)]
	#[length = "8"]
	pub link_layer_address: Vec<u8>,
	
	#[payload]
	pub payload: Vec<u8>
}
