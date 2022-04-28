// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An ICMP packet abstraction.

use crate::PrimitiveValues;

use alloc::vec::Vec;

use pnet_macros::packet;
use pnet_macros_support::types::*;

/// Represents the "ICMP type" header field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IcmpType(pub u8);

impl IcmpType {
    /// Create a new `IcmpType` instance.
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IcmpCode(pub u8);

impl IcmpCode {
    /// Create a new `IcmpCode` instance.
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

/// Represents a generic ICMP packet.
#[packet]
pub struct Icmp {
    #[construct_with(u8)]
    pub icmp_type: IcmpType,
    #[construct_with(u8)]
    pub icmp_code: IcmpCode,
    pub checksum: u16be,
    // theoretically, the header is 64 bytes long, but since the "Rest Of Header" part depends on
    // the ICMP type and ICMP code, we consider it's part of the payload.
    // rest_of_header: u32be,
    #[payload]
    pub payload: Vec<u8>,
}

/// Calculates a checksum of an ICMP packet.
pub fn checksum(packet: &IcmpPacket) -> u16be {
    use crate::Packet;
    use crate::util;

    util::checksum(packet.packet(), 1)
}

#[cfg(test)]
mod checksum_tests {
    use alloc::vec;
    use super::*;

    #[test]
    fn checksum_zeros() {
        let mut data = vec![0u8; 8];
        let expected = 65535;
        let mut pkg = MutableIcmpPacket::new(&mut data[..]).unwrap();
        assert_eq!(checksum(&pkg.to_immutable()), expected);
        pkg.set_checksum(123);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }

    #[test]
    fn checksum_nonzero() {
        let mut data = vec![255u8; 8];
        let expected = 0;
        let mut pkg = MutableIcmpPacket::new(&mut data[..]).unwrap();
        assert_eq!(checksum(&pkg.to_immutable()), expected);
        pkg.set_checksum(0);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }

    #[test]
    fn checksum_odd_bytes() {
        let mut data = vec![191u8; 7];
        let expected = 49535;
        let pkg = IcmpPacket::new(&mut data[..]).unwrap();
        assert_eq!(checksum(&pkg), expected);
    }
}


/// The enumeration of the recognized ICMP types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod IcmpTypes {

    use crate::icmp::IcmpType;
    /// ICMP type for "echo reply" packet.
    pub const EchoReply: IcmpType = IcmpType(0);
    /// ICMP type for "destination unreachable" packet.
    pub const DestinationUnreachable: IcmpType = IcmpType(3);
    /// ICMP type for "source quench" packet.
    pub const SourceQuench: IcmpType = IcmpType(4);
    /// ICMP type for "redirect message" packet.
    pub const RedirectMessage: IcmpType = IcmpType(5);
    /// ICMP type for "echo request" packet.
    pub const EchoRequest: IcmpType = IcmpType(8);
    /// ICMP type for "router advertisement" packet.
    pub const RouterAdvertisement: IcmpType = IcmpType(9);
    /// ICMP type for "router solicitation" packet.
    pub const RouterSolicitation: IcmpType = IcmpType(10);
    /// ICMP type for "time exceeded" packet.
    pub const TimeExceeded: IcmpType = IcmpType(11);
    /// ICMP type for "parameter problem" packet.
    pub const ParameterProblem: IcmpType = IcmpType(12);
    /// ICMP type for "timestamp" packet.
    pub const Timestamp: IcmpType = IcmpType(13);
    /// ICMP type for "timestamp reply" packet.
    pub const TimestampReply: IcmpType = IcmpType(14);
    /// ICMP type for "information request" packet.
    pub const InformationRequest: IcmpType = IcmpType(15);
    /// ICMP type for "information reply" packet.
    pub const InformationReply: IcmpType = IcmpType(16);
    /// ICMP type for "address mask request" packet.
    pub const AddressMaskRequest: IcmpType = IcmpType(17);
    /// ICMP type for "address mask reply" packet.
    pub const AddressMaskReply: IcmpType = IcmpType(18);
    /// ICMP type for "traceroute" packet.
    pub const Traceroute: IcmpType = IcmpType(30);
}


pub mod echo_reply {
    //! abstraction for ICMP "echo reply" packets.
    //!
    //! ```text
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Type      |     Code      |          Checksum             |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |           Identifier          |        Sequence Number        |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Data ...
    //! +-+-+-+-+-
    //! ```

    use crate::PrimitiveValues;
    use crate::icmp::{IcmpCode, IcmpType};

    use alloc::vec::Vec;

    use pnet_macros::packet;
    use pnet_macros_support::types::*;

    /// Represent the "identifier" field of the ICMP echo replay header.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Identifier(pub u16);

    impl Identifier {
        /// Create a new `Identifier` instance.
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
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SequenceNumber(pub u16);

    impl SequenceNumber {
        /// Create a new `SequenceNumber` instance.
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
    pub mod IcmpCodes {
        use crate::icmp::IcmpCode;
        /// 0 is the only available ICMP code for "echo reply" ICMP packets.
        pub const NoCode: IcmpCode = IcmpCode(0);
    }

    /// Represents an ICMP echo reply packet.
    #[packet]
    pub struct EchoReply {
        #[construct_with(u8)]
        pub icmp_type: IcmpType,
        #[construct_with(u8)]
        pub icmp_code: IcmpCode,
        pub checksum: u16be,
        pub identifier: u16be,
        pub sequence_number: u16be,
        #[payload]
        pub payload: Vec<u8>,
    }
}

pub mod echo_request {
    //! abstraction for "echo request" ICMP packets.
    //!
    //! ```text
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Type      |     Code      |          Checksum             |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |           Identifier          |        Sequence Number        |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Data ...
    //! +-+-+-+-+-
    //! ```

    use crate::PrimitiveValues;
    use crate::icmp::{IcmpCode, IcmpType};

    use alloc::vec::Vec;

    use pnet_macros::packet;
    use pnet_macros_support::types::*;

    /// Represents the identifier field.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Identifier(pub u16);

    impl Identifier {
        /// Create a new `Identifier` instance.
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

    /// Represents the sequence number field.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SequenceNumber(pub u16);

    impl SequenceNumber {
        /// Create a new `SequenceNumber` instance.
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
    pub mod IcmpCodes {
        use crate::icmp::IcmpCode;
        /// 0 is the only available ICMP code for "echo reply" ICMP packets.
        pub const NoCode: IcmpCode = IcmpCode(0);
    }

    /// Represents an "echo request" ICMP packet.
    #[packet]
    pub struct EchoRequest {
        #[construct_with(u8)]
        pub icmp_type: IcmpType,
        #[construct_with(u8)]
        pub icmp_code: IcmpCode,
        pub checksum: u16be,
        pub identifier: u16be,
        pub sequence_number: u16be,
        #[payload]
        pub payload: Vec<u8>,
    }
}

pub mod destination_unreachable {
    //! abstraction for "destination unreachable" ICMP packets.
    //!
    //! ```text
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Type      |     Code      |          Checksum             |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |                             unused                            |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |      Internet Header + 64 bits of Original Data Datagram      |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! ```

    use crate::icmp::{IcmpCode, IcmpType};

    use alloc::vec::Vec;

    use pnet_macros::packet;
    use pnet_macros_support::types::*;

    /// Enumeration of the recognized ICMP codes for "destination unreachable" ICMP packets.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod IcmpCodes {
        use crate::icmp::IcmpCode;
        /// ICMP code for "destination network unreachable" packet.
        pub const DestinationNetworkUnreachable: IcmpCode = IcmpCode(0);
        /// ICMP code for "destination host unreachable" packet.
        pub const DestinationHostUnreachable: IcmpCode = IcmpCode(1);
        /// ICMP code for "destination protocol unreachable" packet.
        pub const DestinationProtocolUnreachable: IcmpCode = IcmpCode(2);
        /// ICMP code for "destination port unreachable" packet.
        pub const DestinationPortUnreachable: IcmpCode = IcmpCode(3);
        /// ICMP code for "fragmentation required and DFF flag set" packet.
        pub const FragmentationRequiredAndDFFlagSet: IcmpCode = IcmpCode(4);
        /// ICMP code for "source route failed" packet.
        pub const SourceRouteFailed: IcmpCode = IcmpCode(5);
        /// ICMP code for "destination network unknown" packet.
        pub const DestinationNetworkUnknown: IcmpCode = IcmpCode(6);
        /// ICMP code for "destination host unknown" packet.
        pub const DestinationHostUnknown: IcmpCode = IcmpCode(7);
        /// ICMP code for "source host isolated" packet.
        pub const SourceHostIsolated: IcmpCode = IcmpCode(8);
        /// ICMP code for "network administrative prohibited" packet.
        pub const NetworkAdministrativelyProhibited: IcmpCode = IcmpCode(9);
        /// ICMP code for "host administrative prohibited" packet.
        pub const HostAdministrativelyProhibited: IcmpCode = IcmpCode(10);
        /// ICMP code for "network unreachable for this Type Of Service" packet.
        pub const NetworkUnreachableForTOS: IcmpCode = IcmpCode(11);
        /// ICMP code for "host unreachable for this Type Of Service" packet.
        pub const HostUnreachableForTOS: IcmpCode = IcmpCode(12);
        /// ICMP code for "communication administratively prohibited" packet.
        pub const CommunicationAdministrativelyProhibited: IcmpCode = IcmpCode(13);
        /// ICMP code for "host precedence violation" packet.
        pub const HostPrecedenceViolation: IcmpCode = IcmpCode(14);
        /// ICMP code for "precedence cut off in effect" packet.
        pub const PrecedenceCutoffInEffect: IcmpCode = IcmpCode(15);
    }

    /// Represents an "echo request" ICMP packet.
    #[packet]
    pub struct DestinationUnreachable {
        #[construct_with(u8)]
        pub icmp_type: IcmpType,
        #[construct_with(u8)]
        pub icmp_code: IcmpCode,
        pub checksum: u16be,
        pub unused: u32be,
        #[payload]
        pub payload: Vec<u8>,
    }
}


pub mod time_exceeded {
    //! abstraction for "time exceeded" ICMP packets.
    //!
    //! ```text
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Type      |     Code      |          Checksum             |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |                             unused                            |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |      Internet Header + 64 bits of Original Data Datagram      |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! ```

    use crate::icmp::{IcmpCode, IcmpType};

    use alloc::vec::Vec;

    use pnet_macros::packet;
    use pnet_macros_support::types::*;

    /// Enumeration of the recognized ICMP codes for "time exceeded" ICMP packets.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod IcmpCodes {
        use crate::icmp::IcmpCode;
        /// ICMP code for "time to live exceeded in transit" packet.
        pub const TimeToLiveExceededInTransit: IcmpCode = IcmpCode(0);
        /// ICMP code for "fragment reassembly time exceeded" packet.
        pub const FragmentReasemblyTimeExceeded: IcmpCode = IcmpCode(1);
    }

    /// Represents an "echo request" ICMP packet.
    #[packet]
    pub struct TimeExceeded {
        #[construct_with(u8)]
        pub icmp_type: IcmpType,
        #[construct_with(u8)]
        pub icmp_code: IcmpCode,
        pub checksum: u16be,
        pub unused: u32be,
        #[payload]
        pub payload: Vec<u8>,
    }
}
