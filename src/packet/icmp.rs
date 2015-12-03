// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ICMP packet abstraction

use packet::{Packet, PrimitiveValues};
use pnet_macros_support::types::*;

/// Represents the "ICMP type" header field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IcmpType(pub u8);

impl IcmpType {
    /// Create an ICMP type
    pub fn new(val: u8) -> IcmpType {
        IcmpType(val)
    }
}

impl PrimitiveValues for IcmpType {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// Represents the "ICMP code" header field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IcmpCode(pub u8);

impl IcmpCode {
    /// Create an ICMP code
    pub fn new(val: u8) -> IcmpCode {
        IcmpCode(val)
    }
}

impl PrimitiveValues for IcmpCode {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// Represents a generic ICMP packet
#[packet]
pub struct Icmp {
    #[construct_with(u8)]
    icmp_type: IcmpType,
    #[construct_with(u8)]
    icmp_code: IcmpCode,
    checksum: u16be,
    // theoritically, the header is 64 bytes long, but since the "Rest Of Header" part depends on
    // the ICMP type and ICMP code, we consider it's part of the payload.
    // rest_of_header: u32be,
    #[payload]
    payload: Vec<u8>,
}

/// Calculates the checksum of an ICMP packet
pub fn checksum(packet: &IcmpPacket) -> u16be {
    use packet::Packet;

    let mut sum = 0u32;
    let mut i = 0;
    while i < packet.packet().len() {
        let word = (packet.packet()[i] as u32) << 8 | packet.packet()[i + 1] as u32;
        sum = sum + word;
        i = i + 2;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

/// Enumeration of the recognized ICMP types
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod icmp_types {

    use packet::icmp::IcmpType;
    /// ICMP type for "echo reply" packet
    pub const EchoReply: IcmpType = IcmpType(0);
    /// ICMP type for "destination unreachable" packet
    pub const DestinationUnreachable: IcmpType = IcmpType(3);
    /// ICMP type for "source quench" packet
    pub const SourceQuench: IcmpType = IcmpType(4);
    /// ICMP type for "redirect message" packet
    pub const RedirectMessage: IcmpType = IcmpType(5);
    /// ICMP type for "echo request" packet
    pub const EchoRequest: IcmpType = IcmpType(8);
    /// ICMP type for "router advertisement" packet
    pub const RouterAdvertisement: IcmpType = IcmpType(9);
    /// ICMP type for "router solicitation" packet
    pub const RouterSolicitation: IcmpType = IcmpType(10);
    /// ICMP type for "time exceeded" packet
    pub const TimeExceeded: IcmpType = IcmpType(11);
    /// ICMP type for "parameter problem" packet
    pub const ParameterProblem: IcmpType = IcmpType(12);
    /// ICMP type for "timestamp" packet
    pub const Timestamp: IcmpType = IcmpType(13);
    /// ICMP type for "timestamp reply" packet
    pub const TimestampReply: IcmpType = IcmpType(14);
    /// ICMP type for "information request" packet
    pub const InformationRequest: IcmpType = IcmpType(15);
    /// ICMP type for "information reply" packet
    pub const InformationReply: IcmpType = IcmpType(16);
    /// ICMP type for "address mask request" packet
    pub const AddressMaskRequest: IcmpType = IcmpType(17);
    /// ICMP type for "address mask reply" packet
    pub const AddressMaskReply: IcmpType = IcmpType(18);
    /// ICMP type for "traceroute" packet
    pub const Traceroute: IcmpType = IcmpType(30);
}
