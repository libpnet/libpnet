// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An ICMPv6 packet abstraction.

use crate::ip::IpNextHeaderProtocols;
use crate::PrimitiveValues;
use pnet_macros::packet;
use pnet_macros_support::types::*;
use std::net::Ipv6Addr;

/// Represents the "ICMPv6 type" header field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Icmpv6Type(pub u8);

impl Icmpv6Type {
    /// Create a new `Icmpv6Type` instance.
    pub fn new(val: u8) -> Icmpv6Type {
        Icmpv6Type(val)
    }
}

impl PrimitiveValues for Icmpv6Type {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// Represents the "ICMPv6 code" header field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Icmpv6Code(pub u8);

impl Icmpv6Code {
    /// Create a new `Icmpv6Code` instance.
    pub fn new(val: u8) -> Icmpv6Code {
        Icmpv6Code(val)
    }
}

impl PrimitiveValues for Icmpv6Code {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// Represents a generic ICMPv6 packet [RFC 4443 § 2.1]
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                         Message Body                          +
/// |                                                               |
/// ```
///
/// [RFC 4443 § 2.1]: https://tools.ietf.org/html/rfc4443#section-2.1
#[packet]
pub struct Icmpv6 {
    #[construct_with(u8)]
    pub icmpv6_type: Icmpv6Type,
    #[construct_with(u8)]
    pub icmpv6_code: Icmpv6Code,
    pub checksum: u16be,
    #[payload]
    pub payload: Vec<u8>,
}

/// Calculates a checksum of an ICMPv6 packet.
pub fn checksum(packet: &Icmpv6Packet, source: &Ipv6Addr, destination: &Ipv6Addr) -> u16be {
    use crate::Packet;
    use crate::util;

    util::ipv6_checksum(packet.packet(), 1, &[], source, destination, IpNextHeaderProtocols::Icmpv6)
}

#[cfg(test)]
mod checksum_tests {
    use super::*;

    #[test]
    fn checksum_echo_request() {
        // The equivalent of your typical ping -6 ::1%lo
        let lo = &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let mut data = vec![
            0x80, // Icmpv6 Type
            0x00, // Code
            0xff, 0xff, // Checksum
            0x00, 0x00, // Id
            0x00, 0x01, // Sequence
            // 56 bytes of "random" data
            0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20,
            0x66, 0x6c, 0x65, 0x73, 0x68, 0x20, 0x77, 0x6f,
            0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73,
            0x20, 0x62, 0x75, 0x74, 0x20, 0x61, 0x20, 0x73,
            0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20,
            0x6b, 0x6e, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20,
            0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20
        ];
        let mut pkg = MutableIcmpv6Packet::new(&mut data[..]).unwrap();
        assert_eq!(checksum(&pkg.to_immutable(), lo, lo), 0x1d2e);

        // Check
        pkg.set_icmpv6_type(Icmpv6Type(0x81));
        assert_eq!(checksum(&pkg.to_immutable(), lo, lo), 0x1c2e);
    }
}


/// The enumeration of the recognized ICMPv6 types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv6Types {
    use crate::icmpv6::Icmpv6Type;
    /// ICMPv6 type for "destination unreachable".
    pub const DestinationUnreachable: Icmpv6Type = Icmpv6Type(1);
    /// ICMPv6 type for "packet too big".
    pub const PacketTooBig: Icmpv6Type = Icmpv6Type(2);
    /// ICMPv6 type for "time exceeded".
    pub const TimeExceeded: Icmpv6Type = Icmpv6Type(3);
    /// ICMPv6 type for "parameter problem".
    pub const ParameterProblem: Icmpv6Type = Icmpv6Type(4);
    /// ICMPv6 type for "echo request".
    pub const EchoRequest: Icmpv6Type = Icmpv6Type(128);
    /// ICMPv6 type for "echo reply".
    pub const EchoReply: Icmpv6Type = Icmpv6Type(129);
    // Neighbor Discovery Protocol [RFC4861]
    /// ICMPv6 type for "router solicitation".
    pub const RouterSolicit: Icmpv6Type = Icmpv6Type(133);
    /// ICMPv6 type for "router advertisement".
    pub const RouterAdvert: Icmpv6Type = Icmpv6Type(134);
    /// ICMPv6 type for "neighbor solicitation".
    pub const NeighborSolicit: Icmpv6Type = Icmpv6Type(135);
    /// ICMPv6 type for "neighbor advertisement".
    pub const NeighborAdvert: Icmpv6Type = Icmpv6Type(136);
    /// ICMPv6 type for "redirect".
    pub const Redirect: Icmpv6Type = Icmpv6Type(137);
}

pub mod ndp {
    //! Abstractions for the Neighbor Discovery Protocol [RFC 4861]
    //!
    //! [RFC 4861]: https://tools.ietf.org/html/rfc4861

    use crate::icmpv6::{Icmpv6Code, Icmpv6Type};
    use crate::PrimitiveValues;
    use crate::Packet;
    use pnet_macros::packet;
    use pnet_macros_support::types::*;
    use std::net::Ipv6Addr;

    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod Icmpv6Codes {
        use crate::icmpv6::Icmpv6Code;
        /// 0 is the only available ICMPv6 Code for the NDP.
        pub const NoCode: Icmpv6Code = Icmpv6Code(0);
    }

    /// Represents a Neighbor Discovery Option Type.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct NdpOptionType(pub u8);

    impl NdpOptionType {
        /// Create a new `NdpOptionType` instance.
        pub fn new(value: u8) -> NdpOptionType {
            NdpOptionType(value)
        }
    }

    impl PrimitiveValues for NdpOptionType {
        type T = (u8,);
        fn to_primitive_values(&self) -> (u8,) {
            (self.0,)
        }
    }

    /// Neighbor Discovery Option Types [RFC 4861 § 4.6]
    ///
    /// [RFC 4861 § 4.6]: https://tools.ietf.org/html/rfc4861#section-4.6
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod NdpOptionTypes {
        use super::NdpOptionType;

        /// Source Link-Layer Address Option [RFC 4861 § 4.6.1]
        ///
        /// ```text
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |     Type      |    Length     |    Link-Layer Address ...
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// [RFC 4861 § 4.6.1]: https://tools.ietf.org/html/rfc4861#section-4.6.1
        pub const SourceLLAddr: NdpOptionType = NdpOptionType(1);

        /// Target Link-Layer Address Option [RFC 4861 § 4.6.1]
        ///
        /// ```text
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |     Type      |    Length     |    Link-Layer Address ...
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// [RFC 4861 § 4.6.1]: https://tools.ietf.org/html/rfc4861#section-4.6.1
        pub const TargetLLAddr: NdpOptionType = NdpOptionType(2);

        /// Prefix Information Option [RFC 4861 § 4.6.2]
        ///
        /// ```text
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                         Valid Lifetime                        |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                       Preferred Lifetime                      |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                           Reserved2                           |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                                                               |
        /// +                                                               +
        /// |                                                               |
        /// +                            Prefix                             +
        /// |                                                               |
        /// +                                                               +
        /// |                                                               |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// [RFC 4861 § 4.6.2]: https://tools.ietf.org/html/rfc4861#section-4.6.2
        pub const PrefixInformation: NdpOptionType = NdpOptionType(3);

        /// Redirected Header Option [RFC 4861 § 4.6.3]
        ///
        /// ```text
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |     Type      |    Length     |            Reserved           |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                           Reserved                            |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                                                               |
        /// ~                       IP header + data                        ~
        /// |                                                               |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// [RFC 4861 § 4.6.3]: https://tools.ietf.org/html/rfc4861#section-4.6.3
        pub const RedirectedHeader: NdpOptionType = NdpOptionType(4);

        /// MTU Option [RFC 4861 § 4.6.4]
        ///
        /// ```text
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |     Type      |    Length     |           Reserved            |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                              MTU                              |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// [RFC 4861 § 4.6.4]: https://tools.ietf.org/html/rfc4861#section-4.6.4
        pub const MTU: NdpOptionType = NdpOptionType(5);
    }

    /// Neighbor Discovery Option [RFC 4861 § 4.6]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |    Length     |              ...              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ~                              ...                              ~
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// [RFC 4861 § 4.6]: https://tools.ietf.org/html/rfc4861#section-4.6
    #[packet]
    pub struct NdpOption {
        #[construct_with(u8)]
        pub option_type: NdpOptionType,
        #[construct_with(u8)]
        pub length: u8,
        #[length_fn = "ndp_option_payload_length"]
        #[payload]
        pub data: Vec<u8>,
    }

    /// Calculate a length of a `NdpOption`'s payload.
    fn ndp_option_payload_length(option: &NdpOptionPacket) -> usize {
        let len = option.get_length();
        if len > 0 {
            ((len * 8) - 2) as usize
        } else {
            0
        }
    }

    /// Router Solicitation Message [RFC 4861 § 4.1]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |     Code      |          Checksum             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                            Reserved                           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Options ...
    /// ```
    ///
    /// [RFC 4861 § 4.1]: https://tools.ietf.org/html/rfc4861#section-4.1
    #[packet]
    pub struct RouterSolicit {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub reserved: u32be,
        #[length_fn = "rs_ndp_options_length"]
        pub options: Vec<NdpOption>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    /// Router Solicit packet calculation for the length of the options.
    fn rs_ndp_options_length(pkt: &RouterSolicitPacket) -> usize {
        if pkt.packet().len() > 8 {
            pkt.packet().len() - 8
        } else {
            0
        }
    }

    /// The enumeration of recognized Router Advert flags.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod RouterAdvertFlags {
        /// "Managed Address Configuration" flag. This is set when
        /// addresses are available via DHCPv6.
        pub const ManagedAddressConf: u8 = 0b10000000;
        /// "Other Configuration" flag. This is set when other
        /// configuration information is available via DHCPv6.
        pub const OtherConf: u8 = 0b01000000;
    }

    /// Router Advertisement Message Format [RFC 4861 § 4.2]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |     Code      |          Checksum             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         Reachable Time                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                          Retrans Timer                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Options ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-
    /// ```
    ///
    /// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
    #[packet]
    pub struct RouterAdvert {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub hop_limit: u8,
        pub flags: u8,
        pub lifetime: u16be,
        pub reachable_time: u32be,
        pub retrans_time: u32be,
        #[length_fn = "ra_ndp_options_length"]
        pub options: Vec<NdpOption>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    /// Router Advert packet calculation for the length of the options.
    fn ra_ndp_options_length(pkt: &RouterAdvertPacket) -> usize {
        if pkt.packet().len() > 16 {
            pkt.packet().len() - 16
        } else {
            0
        }
    }

    /// Neighbor Solicitation Message Format [RFC 4861 § 4.3]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |     Code      |          Checksum             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                           Reserved                            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                       Target Address                          +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Options ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-
    /// ```
    ///
    /// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
    #[packet]
    pub struct NeighborSolicit {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub reserved: u32be,
        #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
        pub target_addr: Ipv6Addr,
        #[length_fn = "ns_ndp_options_length"]
        pub options: Vec<NdpOption>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    /// Neighbor Solicit packet calculation for the length of the options.
    fn ns_ndp_options_length(pkt: &NeighborSolicitPacket) -> usize {
        if pkt.packet().len() > 24 {
            pkt.packet().len() - 24
        } else {
            0
        }
    }

    /// Enumeration of recognized Neighbor Advert flags.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod NeighborAdvertFlags {
        /// Indicates that the sender is a router.
        pub const Router: u8 = 0b10000000;
        /// Indicates that the advertisement was sent due to the receipt of a
        /// Neighbor Solicitation message.
        pub const Solicited: u8 = 0b01000000;
        /// Indicates that the advertisement should override an existing cache
        /// entry.
        pub const Override: u8 = 0b00100000;
    }

    /// Neighbor Advertisement Message Format [RFC 4861 § 4.4]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |     Code      |          Checksum             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |R|S|O|                     Reserved                            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                       Target Address                          +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Options ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-
    /// ```
    ///
    /// [RFC 4861 § 4.4]: https://tools.ietf.org/html/rfc4861#section-4.4
    #[packet]
    pub struct NeighborAdvert {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub flags: u8,
        pub reserved: u24be,
        #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
        pub target_addr: Ipv6Addr,
        #[length_fn = "na_ndp_options_length"]
        pub options: Vec<NdpOption>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    /// Neighbor Advert packet calculation for the length of the options.
    fn na_ndp_options_length(pkt: &NeighborAdvertPacket) -> usize {
        if pkt.packet().len() > 24 {
            pkt.packet().len() - 24
        } else {
            0
        }
    }

    /// Redirect Message Format [RFC 4861 § 4.5]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |     Code      |          Checksum             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                           Reserved                            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                       Target Address                          +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                     Destination Address                       +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Options ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-
    /// ```
    ///
    /// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
    #[packet]
    pub struct Redirect {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub reserved: u32be,
        #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
        pub target_addr: Ipv6Addr,
        #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
        pub dest_addr: Ipv6Addr,
        #[length_fn = "redirect_options_length"]
        pub options: Vec<NdpOption>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    /// Redirect packet calculation for the length of the options.
    fn redirect_options_length(pkt: &RedirectPacket) -> usize {
        if pkt.packet().len() > 40 {
            pkt.packet().len() - 40
        } else {
            0
        }
    }

    #[cfg(test)]
    mod ndp_tests {
        use crate::icmpv6::{Icmpv6Types, Icmpv6Code};
        use super::*;

        #[test]
        fn basic_option_parsing() {
            let mut data = vec![
                0x02, 0x01, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                // Extra bytes to confuse the parsing
                0x00, 0x00, 0x00
            ];
            let pkg = MutableNdpOptionPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_option_type(), NdpOptionTypes::TargetLLAddr);
            assert_eq!(pkg.get_length(), 0x01);
            assert_eq!(pkg.payload().len(), 6);
            assert_eq!(pkg.payload(), &[0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        }

        #[test]
        fn basic_rs_parse() {
            let mut data = vec![
                0x85, // Type
                0x00, // Code
                0x00, 0x00, // Checksum
                0x00, 0x00, 0x00, 0x00, // Reserved
                0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];

            let pkg = MutableRouterSolicitPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_icmpv6_type(), Icmpv6Types::RouterSolicit);
            assert_eq!(pkg.get_icmpv6_code(), Icmpv6Code(0));
            assert_eq!(pkg.get_checksum(), 0);
            assert_eq!(pkg.get_reserved(), 0);
            assert_eq!(pkg.get_options().len(), 2);

            let option = &pkg.get_options()[0];
            assert_eq!(option.option_type, NdpOptionTypes::TargetLLAddr);
            assert_eq!(option.length, 0x01);
            assert_eq!(option.data, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            assert_eq!(option.data.len(), 6);

            let option = &pkg.get_options()[1];
            assert_eq!(option.option_type, NdpOptionTypes::SourceLLAddr);
            assert_eq!(option.length, 1);
            assert_eq!(option.data, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn basic_rs_create() {
            let ref_packet = vec![
                0x85, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x01, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ];
            let mut packet = [0u8; 16];
            let options = vec![
                NdpOption {
                    option_type: NdpOptionTypes::SourceLLAddr,
                    length: 1,
                    data: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                }
            ];
            {
                let mut rs_packet = MutableRouterSolicitPacket::new(&mut packet[..]).unwrap();
                rs_packet.set_icmpv6_type(Icmpv6Types::RouterSolicit);
                rs_packet.set_icmpv6_code(Icmpv6Code(0));
                rs_packet.set_options(&options[..]);
            }
            assert_eq!(&ref_packet[..], &packet[..]);
        }

        #[test]
        fn basic_ra_parse() {
            let mut data = vec![
                0x86, // Type
                0x00, // Code
                0x00, 0x00, // Checksum
                0xff, // Hop Limit
                0x80, // Flags
                0x09, 0x00, // Lifetime
                0x12, 0x34, 0x56, 0x78, // Reachable
                0x87, 0x65, 0x43, 0x21, // Retrans
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Link-Layer
                0x05, 0x01, 0x00, 0x00, 0x57, 0x68, 0x61, 0x74 // MTU
            ];
            let pkg = MutableRouterAdvertPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_icmpv6_type(), Icmpv6Types::RouterAdvert);
            assert_eq!(pkg.get_icmpv6_code(), Icmpv6Code(0));
            assert_eq!(pkg.get_checksum(), 0x00);
            assert_eq!(pkg.get_hop_limit(), 0xff);
            assert_eq!(pkg.get_flags(), RouterAdvertFlags::ManagedAddressConf);
            assert_eq!(pkg.get_lifetime(), 0x900);
            assert_eq!(pkg.get_reachable_time(), 0x12345678);
            assert_eq!(pkg.get_retrans_time(), 0x87654321);
            assert_eq!(pkg.get_options().len(), 2);

            let option = &pkg.get_options()[0];
            assert_eq!(option.option_type, NdpOptionTypes::SourceLLAddr);
            assert_eq!(option.length, 1);
            assert_eq!(option.data, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

            let option = &pkg.get_options()[1];
            assert_eq!(option.option_type, NdpOptionTypes::MTU);
            assert_eq!(option.length, 1);
            assert_eq!(option.data, &[0x00, 0x00, 0x57, 0x68, 0x61, 0x74]);
        }

        #[test]
        fn basic_ra_create() {
            let ref_packet = vec![
                0x86, 0x00, 0x00, 0x00,
                0xff, 0x80, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x05, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ];
            let mut packet = [0u8; 24];
            let options = vec![
                NdpOption {
                    option_type: NdpOptionTypes::MTU,
                    length: 1,
                    data: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                }
            ];
            {
                let mut ra_packet = MutableRouterAdvertPacket::new(&mut packet[..]).unwrap();
                ra_packet.set_icmpv6_type(Icmpv6Types::RouterAdvert);
                ra_packet.set_icmpv6_code(Icmpv6Code(0));
                ra_packet.set_hop_limit(0xff);
                ra_packet.set_flags(RouterAdvertFlags::ManagedAddressConf);
                ra_packet.set_options(&options[..]);
            }
            assert_eq!(&ref_packet[..], &packet[..]);
        }

        #[test]
        fn basic_ns_parse() {
            let mut data = vec![
                0x87, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01
            ];
            let pkg = MutableNeighborSolicitPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_icmpv6_type(), Icmpv6Types::NeighborSolicit);
            assert_eq!(pkg.get_icmpv6_code(), Icmpv6Code(0));
            assert_eq!(pkg.get_checksum(), 0x00);
            assert_eq!(pkg.get_reserved(), 0x00);
            assert_eq!(pkg.get_target_addr(), Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        }

        #[test]
        fn basic_ns_create() {
            let ref_packet = vec![
                0x87, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ];
            let mut packet = [0u8; 24];
            {
                let mut ns_packet = MutableNeighborSolicitPacket::new(&mut packet[..]).unwrap();
                ns_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
                ns_packet.set_icmpv6_code(Icmpv6Code(0));
                ns_packet.set_target_addr(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
            }
            assert_eq!(&ref_packet[..], &packet[..]);
        }

        #[test]
        fn basic_na_parse() {
            let mut data = vec![
                0x88, 0x00, 0x00, 0x00,
                0x80, 0x00, 0x00, 0x00,
                0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01
            ];
            let pkg = MutableNeighborAdvertPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_icmpv6_type(), Icmpv6Types::NeighborAdvert);
            assert_eq!(pkg.get_icmpv6_code(), Icmpv6Code(0));
            assert_eq!(pkg.get_checksum(), 0x00);
            assert_eq!(pkg.get_reserved(), 0x00);
            assert_eq!(pkg.get_flags(), 0x80);
            assert_eq!(pkg.get_target_addr(), Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        }

        #[test]
        fn basic_na_create() {
            let ref_packet = vec![
                0x88, 0x00, 0x00, 0x00,
                0x80, 0x00, 0x00, 0x00,
                0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ];
            let mut packet = [0u8; 24];
            {
                let mut na_packet = MutableNeighborAdvertPacket::new(&mut packet[..]).unwrap();
                na_packet.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
                na_packet.set_icmpv6_code(Icmpv6Code(0));
                na_packet.set_target_addr(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
                na_packet.set_flags(NeighborAdvertFlags::Router);
            }
            assert_eq!(&ref_packet[..], &packet[..]);
        }

        #[test]
        fn basic_redirect_parse() {
            let mut data = vec![
                0x89, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ];
            let pkg = MutableRedirectPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_icmpv6_type(), Icmpv6Types::Redirect);
            assert_eq!(pkg.get_icmpv6_code(), Icmpv6Code(0));
            assert_eq!(pkg.get_checksum(), 0x00);
            assert_eq!(pkg.get_reserved(), 0x00);
            assert_eq!(pkg.get_target_addr(), Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
            assert_eq!(pkg.get_dest_addr(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        }

        #[test]
        fn basic_redirect_create() {
            let ref_packet = vec![
                0x89, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ];
            let mut packet = [0u8; 40];
            {
                let mut rdr_packet = MutableRedirectPacket::new(&mut packet[..]).unwrap();
                rdr_packet.set_icmpv6_type(Icmpv6Types::Redirect);
                rdr_packet.set_icmpv6_code(Icmpv6Code(0));
                rdr_packet.set_target_addr(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
                rdr_packet.set_dest_addr(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
            }
            assert_eq!(&ref_packet[..], &packet[..]);
        }
    }
}

pub mod echo_reply {
    //! abstraction for "echo reply" ICMPv6 packets.
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
    use crate::icmpv6::{Icmpv6Code, Icmpv6Type};
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

    /// Enumeration of available ICMPv6 codes for "echo reply" ICMPv6 packets. There is actually only
    /// one, since the only valid ICMPv6 code is 0.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod Icmpv6Codes {
        use crate::icmpv6::Icmpv6Code;
        /// 0 is the only available ICMPv6 code for "echo reply" ICMPv6 packets.
        pub const NoCode: Icmpv6Code = Icmpv6Code(0);
    }

    /// Represents an "echo reply" ICMPv6 packet.
    #[packet]
    pub struct EchoReply {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub identifier: u16be,
        pub sequence_number: u16be,
        #[payload]
        pub payload: Vec<u8>,
    }
}

pub mod echo_request {
    //! abstraction for "echo request" ICMPv6 packets.
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
    use crate::icmpv6::{Icmpv6Code, Icmpv6Type};
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

    /// Enumeration of available ICMPv6 codes for "echo reply" ICMPv6 packets. There is actually only
    /// one, since the only valid ICMPv6 code is 0.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod Icmpv6Codes {
        use crate::icmpv6::Icmpv6Code;
        /// 0 is the only available ICMPv6 code for "echo reply" ICMPv6 packets.
        pub const NoCode: Icmpv6Code = Icmpv6Code(0);
    }

    /// Represents an "echo request" ICMPv6 packet.
    #[packet]
    pub struct EchoRequest {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub identifier: u16be,
        pub sequence_number: u16be,
        #[payload]
        pub payload: Vec<u8>,
    }
}
