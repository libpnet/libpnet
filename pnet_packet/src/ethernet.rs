// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An ethernet packet abstraction.

use crate::PrimitiveValues;

use alloc::vec::Vec;
use core::fmt;

use pnet_base::MacAddr;
use pnet_macros::packet;

/// Represents an Ethernet packet.
#[packet]
pub struct Ethernet {
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub destination: MacAddr,
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub source: MacAddr,
    #[construct_with(u16)]
    pub ethertype: EtherType,
    #[payload]
    pub payload: Vec<u8>,
}

#[test]
fn ethernet_header_test() {
    let mut packet = [0u8; 14];
    {
        let mut ethernet_header = MutableEthernetPacket::new(&mut packet[..]).unwrap();

        let source = MacAddr(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        ethernet_header.set_source(source);
        assert_eq!(ethernet_header.get_source(), source);

        let dest = MacAddr(0xde, 0xf0, 0x12, 0x34, 0x45, 0x67);
        ethernet_header.set_destination(dest);
        assert_eq!(ethernet_header.get_destination(), dest);

        ethernet_header.set_ethertype(EtherTypes::Ipv6);
        assert_eq!(ethernet_header.get_ethertype(), EtherTypes::Ipv6);
    }

    let ref_packet = [0xde, 0xf0, 0x12, 0x34, 0x45, 0x67, /* destination */
                      0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, /* source */
                      0x86, 0xdd /* ethertype */];
    assert_eq!(&ref_packet[..], &packet[..]);
}

/// `EtherTypes` are defined at:
/// <http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml>.
/// These values should be used in the `Ethernet` `EtherType` field.
///
/// FIXME Should include all
/// A handful of these have been selected since most are archaic and unused.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod EtherTypes {
    use crate::ethernet::EtherType;

    /// Internet Protocol version 4 (IPv4) \[RFC7042\].
    pub const Ipv4: EtherType = EtherType(0x0800);
    /// Address Resolution Protocol (ARP) \[RFC7042\].
    pub const Arp: EtherType = EtherType(0x0806);
    /// Wake on Lan.
    pub const WakeOnLan: EtherType = EtherType(0x0842);
    /// IETF TRILL Protocol \[IEEE\].
    pub const Trill: EtherType = EtherType(0x22F3);
    /// DECnet Phase IV.
    pub const DECnet: EtherType = EtherType(0x6003);
    /// Reverse Address Resolution Protocol (RARP) \[RFC903\].
    pub const Rarp: EtherType = EtherType(0x8035); 
    /// AppleTalk - EtherTalk \[Apple\].
    pub const AppleTalk: EtherType = EtherType(0x809B);
    /// AppleTalk Address Resolution Protocol (AARP) \[Apple\].
    pub const Aarp: EtherType = EtherType(0x80F3);
    /// IPX \[Xerox\].
    pub const Ipx: EtherType = EtherType(0x8137);
    /// QNX Qnet \[QNX Software Systems\].
    pub const Qnx: EtherType = EtherType(0x8204);
    /// Internet Protocol version 6 (IPv6) \[RFC7042\].
    pub const Ipv6: EtherType = EtherType(0x86DD);
    /// Ethernet Flow Control \[IEEE 802.3x\].
    pub const FlowControl: EtherType = EtherType(0x8808);
    /// CobraNet \[CobraNet\].
    pub const CobraNet: EtherType = EtherType(0x8819);
    /// MPLS Unicast \[RFC 3032\].
    pub const Mpls: EtherType = EtherType(0x8847);
    /// MPLS Multicast \[RFC 5332\].
    pub const MplsMcast: EtherType = EtherType(0x8848);
    /// PPPOE Discovery Stage \[RFC 2516\].
    pub const PppoeDiscovery: EtherType = EtherType(0x8863);
    /// PPPoE Session Stage \[RFC 2516\].
    pub const PppoeSession: EtherType = EtherType(0x8864);
    /// VLAN-tagged frame (IEEE 802.1Q).
    pub const Vlan: EtherType = EtherType(0x8100);
    /// Provider Bridging \[IEEE 802.1ad / IEEE 802.1aq\].
    pub const PBridge: EtherType = EtherType(0x88a8);
    /// Link Layer Discovery Protocol (LLDP) \[IEEE 802.1AB\].
    pub const Lldp: EtherType = EtherType(0x88cc);
    /// Precision Time Protocol (PTP) over Ethernet \[IEEE 1588\].
    pub const Ptp: EtherType = EtherType(0x88f7);
    /// CFM / Y.1731 \[IEEE 802.1ag\].
    pub const Cfm: EtherType = EtherType(0x8902);
    /// Q-in-Q Vlan Tagging \[IEEE 802.1Q\].
    pub const QinQ: EtherType = EtherType(0x9100);
}

/// Represents the `Ethernet::ethertype` field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EtherType(pub u16);

impl EtherType {
    /// Construct a new `EtherType` instance.
    pub fn new(val: u16) -> EtherType {
        EtherType(val)
    }
}

impl PrimitiveValues for EtherType {
    type T = (u16,);
    fn to_primitive_values(&self) -> (u16,) {
        (self.0,)
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "{}",
               match self {
                   &EtherTypes::Ipv4 => "Ipv4", //(0x0800)
                   &EtherTypes::Arp => "Arp", //(0x0806)
                   &EtherTypes::WakeOnLan => "WakeOnLan", //(0x0842)
                   &EtherTypes::Trill => "Trill", //(0x22F3)
                   &EtherTypes::DECnet => "DECnet", //(0x6003)
                   &EtherTypes::Rarp => "Rarp", //(0x8035)
                   &EtherTypes::AppleTalk => "AppleTalk", //(0x809B)
                   &EtherTypes::Aarp => "Aarp", //(0x80F3)
                   &EtherTypes::Ipx => "Ipx", //(0x8137)
                   &EtherTypes::Qnx => "Qnx", //(0x8204)
                   &EtherTypes::Ipv6 => "Ipv6", //(0x86DD)
                   &EtherTypes::FlowControl => "FlowControl", //(0x8808)
                   &EtherTypes::CobraNet => "CobraNet", //(0x8819)
                   &EtherTypes::Mpls => "Mpls", //(0x8847)
                   &EtherTypes::MplsMcast => "MplsMcast", //(0x8848)
                   &EtherTypes::PppoeDiscovery => "PppoeDiscovery", //(0x8863)
                   &EtherTypes::PppoeSession => "PppoeSession", //(0x8864)
                   &EtherTypes::Vlan => "Vlan", //(0x8100)
                   &EtherTypes::PBridge => "PBridge", //(0x88a8)
                   &EtherTypes::Lldp => "Lldp", //(0x88cc)
                   &EtherTypes::Ptp => "Ptp", //(0x88f7)
                   &EtherTypes::Cfm => "Cfm", //(0x8902)
                   &EtherTypes::QinQ => "QinQ", //(0x9100)
                   _ => "unknown",
               })
    }
}

#[cfg(feature = "std")]
#[test]
fn ether_type_to_str() {
    use std::format;
    let ipv4 = EtherType(0x0800);
    assert_eq!(format!("{}", ipv4), "Ipv4");
    let arp = EtherType(0x0806);
    assert_eq!(format!("{}", arp), "Arp");
    let unknown = EtherType(0x0666);
    assert_eq!(format!("{}", unknown), "unknown");
}

