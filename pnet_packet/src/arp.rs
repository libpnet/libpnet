// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ARP packet abstraction.

use crate::PrimitiveValues;
use crate::ethernet::EtherType;

use alloc::vec::Vec;

use pnet_base::core_net::Ipv4Addr;
use pnet_base::MacAddr;
use pnet_macros::packet;

/// Represents an ARP operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArpOperation(pub u16);

impl ArpOperation {
    /// Create a new `ArpOperation`.
    pub fn new(value: u16) -> Self {
        ArpOperation(value)
    }
}

impl PrimitiveValues for ArpOperation {
    type T = (u16,);
    fn to_primitive_values(&self) -> (u16,) {
        (self.0,)
    }
}

/// The ARP protocol operations.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod ArpOperations {
    use super::ArpOperation;

    /// ARP request
    pub const Request: ArpOperation = ArpOperation(1);

    /// ARP reply
    pub const Reply: ArpOperation = ArpOperation(2);
}

/// Represents the ARP hardware types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArpHardwareType(pub u16);

impl ArpHardwareType {
    /// Create a new `ArpHardwareType`.
    pub fn new(value: u16) -> Self {
        ArpHardwareType(value)
    }
}

impl PrimitiveValues for ArpHardwareType {
    type T = (u16,);
    fn to_primitive_values(&self) -> (u16,) {
        (self.0,)
    }
}

/// The ARP protocol hardware types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod ArpHardwareTypes {
    use super::ArpHardwareType;

    /// Ethernet
    pub const Ethernet: ArpHardwareType = ArpHardwareType(1);
}

/// Represents an ARP Packet.
#[packet]
#[allow(non_snake_case)]
pub struct Arp {
    #[construct_with(u16)]
    pub hardware_type: ArpHardwareType,
    #[construct_with(u16)]
    pub protocol_type: EtherType,
    // We completely ignore hw_addr_len and
    // proto_addr_len and use values for
    // Ipv4 on top of Ethernet as it's the
    // most common use case
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    #[construct_with(u16)]
    pub operation: ArpOperation,
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub sender_hw_addr: MacAddr,
    #[construct_with(u8, u8, u8, u8)]
    pub sender_proto_addr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub target_hw_addr: MacAddr,
    #[construct_with(u8, u8, u8, u8)]
    pub target_proto_addr: Ipv4Addr,
    #[payload]
    #[length = "0"]
    pub payload: Vec<u8>,
}
