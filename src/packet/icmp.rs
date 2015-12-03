// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ICMP packet abstraction

#[cfg(test)]
extern crate pcapng;

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


/// abstraction for ICMP echo reply packets
pub mod echo_reply {
    use packet::{Packet, PrimitiveValues};
    use packet::icmp::{IcmpCode, IcmpType};
    use pnet_macros_support::types::*;

    /// Represent the "identifier" field of the ICMP echo replay header.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Identifier(pub u16);

    impl Identifier {
        /// Create an identifier
        pub fn new(val: u16) -> Identifier {
            Identifier(val)
        }
    }

    impl PrimitiveValues for Identifier {
        type T = (u16,);
        fn to_primitive_values(&self) -> (u16,) {
            (self.0,)
        }
    }

    /// Represent the "sequence number" field of the ICMP echo replay header.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct SequenceNumber(pub u16);

    impl SequenceNumber {
        /// Create a sequence number
        pub fn new(val: u16) -> SequenceNumber {
            SequenceNumber(val)
        }
    }

    impl PrimitiveValues for SequenceNumber {
        type T = (u16,);
        fn to_primitive_values(&self) -> (u16,) {
            (self.0,)
        }
    }

    /// Enumeration of available ICMP codes for ICMP echo replay packets. There is actually only
    /// one, since the only valid ICMP code is 0.
    #[allow(non_snake_case)]
	#[allow(non_upper_case_globals)]
    pub mod icmp_codes {
        use packet::icmp::IcmpCode;
        /// 0 is the only available ICMP code for "echo reply" ICMP packets.
        pub const NoCode: IcmpCode = IcmpCode(0);
    }

    /// Represents an ICMP echo reply packet.
    #[packet]
    pub struct EchoReply {
        #[construct_with(u8)]
        icmp_type: IcmpType,
        #[construct_with(u8)]
        icmp_code: IcmpCode,
        checksum: u16be,
        identifier: u16be,
        sequence_number: u16be,
        #[payload]
        payload: Vec<u8>,
    }
}

/// abstraction for "echo request" ICMP packets.
pub mod echo_request {
    use packet::{Packet, PrimitiveValues};
    use packet::icmp::{IcmpCode, IcmpType};
    use pnet_macros_support::types::*;

    /// Represents an indentifier field
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Identifier(pub u16);

    impl Identifier {
        /// Create an identifier
        pub fn new(val: u16) -> Identifier {
            Identifier(val)
        }
    }

    impl PrimitiveValues for Identifier {
        type T = (u16,);
        fn to_primitive_values(&self) -> (u16,) {
            (self.0,)
        }
    }

    /// Represents a sequence number field
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct SequenceNumber(pub u16);

    impl SequenceNumber {
        /// Create a sequence number
        pub fn new(val: u16) -> SequenceNumber {
            SequenceNumber(val)
        }
    }

    impl PrimitiveValues for SequenceNumber {
        type T = (u16,);
        fn to_primitive_values(&self) -> (u16,) {
            (self.0,)
        }
    }

    /// Enumeration of available ICMP codes for "echo reply" ICMP packets. There is actually only
    /// one, since the only valid ICMP code is 0.
    #[allow(non_snake_case)]
	#[allow(non_upper_case_globals)]
    pub mod icmp_codes {
        use packet::icmp::IcmpCode;
        /// 0 is the only available ICMP code for "echo reply" ICMP packets.
        pub const NoCode: IcmpCode = IcmpCode(0);
    }

    /// Represents an "echo request" ICMP packet.
    #[packet]
    pub struct EchoRequest {
        #[construct_with(u8)]
        icmp_type: IcmpType,
        #[construct_with(u8)]
        icmp_code: IcmpCode,
        checksum: u16be,
        identifier: u16be,
        sequence_number: u16be,
        #[payload]
        payload: Vec<u8>,
    }
}

/// abstraction for "destination unreachable" ICMP packets.
pub mod destination_unreachable {
    use packet::icmp::{IcmpCode, IcmpType};
    use pnet_macros_support::types::*;

    /// Enumeration of the recognized ICMP codes for "destination unreachable" ICMP packets.
    #[allow(non_snake_case)]
	#[allow(non_upper_case_globals)]
    pub mod icmp_codes {
        use packet::icmp::IcmpCode;
        /// ICMP code for "destination network unreachable" packet
        pub const DestinationNetworkUnreachable: IcmpCode = IcmpCode(0);
        /// ICMP code for "destination host unreachable" packet
        pub const DestinationHostUnreachable: IcmpCode = IcmpCode(1);
        /// ICMP code for "destination protocol unreachable" packet
        pub const DestinationProtocolUnreachable: IcmpCode = IcmpCode(2);
        /// ICMP code for "destination port unreachable" packet
        pub const DestinationPortUnreachable: IcmpCode = IcmpCode(3);
        /// ICMP code for "fragmentation required and DFF flag set" packet
        pub const FragmentationRequiredAndDFFlagSet: IcmpCode = IcmpCode(4);
        /// ICMP code for "source route failed" packet
        pub const SourceRouteFailed: IcmpCode = IcmpCode(5);
        /// ICMP code for "destination network unknown" packet
        pub const DestinationNetworkUnknown: IcmpCode = IcmpCode(6);
        /// ICMP code for "destination host unknown" packet
        pub const DestinationHostUnknown: IcmpCode = IcmpCode(7);
        /// ICMP code for "source host isolated" packet
        pub const SourceHostIsolated: IcmpCode = IcmpCode(8);
        /// ICMP code for "network administrative prohibited" packet
        pub const NetworkAdministrativelyProhibited: IcmpCode = IcmpCode(9);
        /// ICMP code for "host administrative prohibited" packet
        pub const HostAdministrativelyProhibited: IcmpCode = IcmpCode(10);
        /// ICMP code for "network unreachable for this Type Of Service" packet
        pub const NetworkUnreachableForTOS: IcmpCode = IcmpCode(11);
        /// ICMP code for "host unreachable for this Type Of Service" packet
        pub const HostUnreachableForTOS: IcmpCode = IcmpCode(12);
        /// ICMP code for "communication administratively prohibited" packet
        pub const CommunicationAdministrativelyProhibited: IcmpCode = IcmpCode(13);
        /// ICMP code for "host precedence violation" packet
        pub const HostPrecedenceViolation: IcmpCode = IcmpCode(14);
        /// ICMP code for "precedence cut off in effect" packet
        pub const PrecedenceCutoffInEffect: IcmpCode = IcmpCode(15);
    }

    /// Represents an "echo request" ICMP packet.
    #[packet]
    pub struct DestinationUnreachable {
        #[construct_with(u8)]
        icmp_type: IcmpType,
        #[construct_with(u8)]
        icmp_code: IcmpCode,
        checksum: u16be,
        unused: u32be,
        #[payload]
        payload: Vec<u8>,
    }
}


#[cfg(test)]
mod tests {
	use super::*;
    use std::fs::File;
    use packet::{Packet, PrimitiveValues};
    use packet::ipv4::{Ipv4Packet};
    use packet::ethernet::{EthernetPacket};
    use pcapng;


	fn get_packet_from_capture(capture_name: &str) -> Vec<u8> {
        let mut path: String = "./test_data/".to_owned();
        path.push_str(capture_name);
        let mut f = File::open(path).unwrap();
        let mut r = pcapng::SimpleReader::new(&mut f);
        let (_, pcapng_packet) = r.packets().next().unwrap();
        let ethernet_packet = EthernetPacket::new(&pcapng_packet.data[..]).unwrap();
        let ip_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();

        // We cannot return the ip_packet payload since the underlying buffer does not exist
        // anymore after this function return. The only solution I found is to manually make a copy
        // of the payload and return it.
        //
        // This seems very clumsy, is there any better way to do this?
        let mut data: Vec<u8> = vec![];
        for byte in ip_packet.payload() {
            data.push(*byte);
        }
        data
    }
}
