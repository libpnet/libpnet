//! A Linux cooked-mode capture v2 (LINKTYPE_LINUX_SLL2) packet abstraction.
// ref: https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html

use alloc::vec::Vec;

use pnet_macros::packet;
use pnet_macros_support::types::*;

use super::ethernet::EtherType;

/// Represents an SLL2 packet (LINKTYPE_LINUX_SLL2).
#[packet]
pub struct SLL2 {
    #[construct_with(u16)]
    pub protocol_type: EtherType,
    
    #[construct_with(u16)]
    pub reserved: u16be,
    
    #[construct_with(u32)]
    pub interface_index: u32be,
    
    #[construct_with(u16)]
    pub arphrd_type: u16be,
    
    #[construct_with(u8)]
    pub packet_type: u8,
    
    #[construct_with(u8)]
    pub link_layer_address_length: u8,
    
    #[construct_with(u8, u8, u8, u8, u8, u8, u8, u8)]
    #[length = "8"]
	pub link_layer_address: Vec<u8>,
    
    #[payload]
	pub payload: Vec<u8>
}
