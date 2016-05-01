// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Defines the type and constants for IP next header/next level protocol
//! fields.

use packet::PrimitiveValues;
use std::fmt;

/// Protocol numbers as defined at:
/// http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
/// Above protocol numbers last updated: 2014-01-16
/// These values should be used in either the IPv4 Next Level Protocol field
/// or the IPv6 Next Header field.
/// NOTE Everything here is pretending to be an enum, but with namespacing by
///      default, so we allow breaking style guidelines.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod IpNextHeaderProtocols {
    use super::IpNextHeaderProtocol;

    /// IPv6 Hop-by-Hop Option [RFC2460]
    pub const Hopopt: IpNextHeaderProtocol = IpNextHeaderProtocol(0);

    /// Internet Control Message [RFC792]
    pub const Icmp: IpNextHeaderProtocol = IpNextHeaderProtocol(1);

    /// Internet Group Management [RFC1112]
    pub const Igmp: IpNextHeaderProtocol = IpNextHeaderProtocol(2);

    /// Gateway-to-Gateway [RFC823]
    pub const Ggp: IpNextHeaderProtocol = IpNextHeaderProtocol(3);

    /// IPv4 encapsulation [RFC2003]
    pub const Ipv4: IpNextHeaderProtocol = IpNextHeaderProtocol(4);

    /// Stream [RFC1190][RFC1819]
    pub const St: IpNextHeaderProtocol = IpNextHeaderProtocol(5);

    /// Transmission Control [RFC793]
    pub const Tcp: IpNextHeaderProtocol = IpNextHeaderProtocol(6);

    /// CBT
    pub const Cbt: IpNextHeaderProtocol = IpNextHeaderProtocol(7);

    /// Exterior Gateway Protocol [RFC888]
    pub const Egp: IpNextHeaderProtocol = IpNextHeaderProtocol(8);

    /// any private interior gateway (used by Cisco for their IGRP)
    pub const Igp: IpNextHeaderProtocol = IpNextHeaderProtocol(9);

    /// BBN RCC Monitoring
    pub const BbnRccMon: IpNextHeaderProtocol = IpNextHeaderProtocol(10);

    /// Network Voice Protocol [RFC741]
    pub const NvpII: IpNextHeaderProtocol = IpNextHeaderProtocol(11);

    /// PUP
    pub const Pup: IpNextHeaderProtocol = IpNextHeaderProtocol(12);

    /// ARGUS
    pub const Argus: IpNextHeaderProtocol = IpNextHeaderProtocol(13);

    /// EMCON
    pub const Emcon: IpNextHeaderProtocol = IpNextHeaderProtocol(14);

    /// Cross Net Debugger
    pub const Xnet: IpNextHeaderProtocol = IpNextHeaderProtocol(15);

    /// Chaos
    pub const Chaos: IpNextHeaderProtocol = IpNextHeaderProtocol(16);

    /// User Datagram [RFC768]
    pub const Udp: IpNextHeaderProtocol = IpNextHeaderProtocol(17);

    /// Multiplexing
    pub const Mux: IpNextHeaderProtocol = IpNextHeaderProtocol(18);

    /// DCN Measurement Subsystems
    pub const DcnMeas: IpNextHeaderProtocol = IpNextHeaderProtocol(19);

    /// Host Monitoring [RFC869]
    pub const Hmp: IpNextHeaderProtocol = IpNextHeaderProtocol(20);

    /// Packet Radio Measurement
    pub const Prm: IpNextHeaderProtocol = IpNextHeaderProtocol(21);

    /// XEROX NS IDP
    pub const XnsIdp: IpNextHeaderProtocol = IpNextHeaderProtocol(22);

    /// Trunk-1
    pub const Trunk1: IpNextHeaderProtocol = IpNextHeaderProtocol(23);

    /// Trunk-2
    pub const Trunk2: IpNextHeaderProtocol = IpNextHeaderProtocol(24);

    /// Leaf-1
    pub const Leaf1: IpNextHeaderProtocol = IpNextHeaderProtocol(25);

    /// Leaf-2
    pub const Leaf2: IpNextHeaderProtocol = IpNextHeaderProtocol(26);

    /// Reliable Data Protocol [RFC908]
    pub const Rdp: IpNextHeaderProtocol = IpNextHeaderProtocol(27);

    /// Internet Reliable Transaction [RFC938]
    pub const Irtp: IpNextHeaderProtocol = IpNextHeaderProtocol(28);

    /// ISO Transport Protocol Class 4 [RFC905]
    pub const IsoTp4: IpNextHeaderProtocol = IpNextHeaderProtocol(29);

    /// Bulk Data Transfer Protocol [RFC969]
    pub const Netblt: IpNextHeaderProtocol = IpNextHeaderProtocol(30);

    /// MFE Network Services Protocol
    pub const MfeNsp: IpNextHeaderProtocol = IpNextHeaderProtocol(31);

    /// MERIT Internodal Protocol
    pub const MeritInp: IpNextHeaderProtocol = IpNextHeaderProtocol(32);

    /// Datagram Congestion Control Protocol [RFC4340]
    pub const Dccp: IpNextHeaderProtocol = IpNextHeaderProtocol(33);

    /// Third Party Connect Protocol
    pub const ThreePc: IpNextHeaderProtocol = IpNextHeaderProtocol(34);

    /// Inter-Domain Policy Routing Protocol
    pub const Idpr: IpNextHeaderProtocol = IpNextHeaderProtocol(35);

    /// XTP
    pub const Xtp: IpNextHeaderProtocol = IpNextHeaderProtocol(36);

    /// Datagram Delivery Protocol
    pub const Ddp: IpNextHeaderProtocol = IpNextHeaderProtocol(37);

    /// IDPR Control Message Transport Proto
    pub const IdprCmtp: IpNextHeaderProtocol = IpNextHeaderProtocol(38);

    /// TP++ Transport Protocol
    pub const TpPlusPlus: IpNextHeaderProtocol = IpNextHeaderProtocol(39);

    /// IL Transport Protocol
    pub const Il: IpNextHeaderProtocol = IpNextHeaderProtocol(40);

    /// IPv6 encapsulation [RFC2473]
    pub const Ipv6: IpNextHeaderProtocol = IpNextHeaderProtocol(41);

    /// Source Demand Routing Protocol
    pub const Sdrp: IpNextHeaderProtocol = IpNextHeaderProtocol(42);

    /// Routing Header for IPv6
    pub const Ipv6Route: IpNextHeaderProtocol = IpNextHeaderProtocol(43);

    /// Fragment Header for IPv6
    pub const Ipv6Frag: IpNextHeaderProtocol = IpNextHeaderProtocol(44);

    /// Inter-Domain Routing Protocol
    pub const Idrp: IpNextHeaderProtocol = IpNextHeaderProtocol(45);

    /// Reservation Protocol [RFC2205][RFC3209]
    pub const Rsvp: IpNextHeaderProtocol = IpNextHeaderProtocol(46);

    /// Generic Routing Encapsulation [RFC1701]
    pub const Gre: IpNextHeaderProtocol = IpNextHeaderProtocol(47);

    /// Dynamic Source Routing Protocol [RFC4728]
    pub const Dsr: IpNextHeaderProtocol = IpNextHeaderProtocol(48);

    /// BNA
    pub const Bna: IpNextHeaderProtocol = IpNextHeaderProtocol(49);

    /// Encap Security Payload [RFC4303]
    pub const Esp: IpNextHeaderProtocol = IpNextHeaderProtocol(50);

    /// Authentication Header [RFC4302]
    pub const Ah: IpNextHeaderProtocol = IpNextHeaderProtocol(51);

    /// Integrated Net Layer Security TUBA
    pub const INlsp: IpNextHeaderProtocol = IpNextHeaderProtocol(52);

    /// IP with Encryption
    pub const Swipe: IpNextHeaderProtocol = IpNextHeaderProtocol(53);

    /// NBMA Address Resolution Protocol [RFC1735]
    pub const Narp: IpNextHeaderProtocol = IpNextHeaderProtocol(54);

    /// IP Mobility
    pub const Mobile: IpNextHeaderProtocol = IpNextHeaderProtocol(55);

    /// Transport Layer Security Protocol using Kryptonet key management
    pub const Tlsp: IpNextHeaderProtocol = IpNextHeaderProtocol(56);

    /// SKIP
    pub const Skip: IpNextHeaderProtocol = IpNextHeaderProtocol(57);

    /// ICMP for IPv6 [RFC2460]
    pub const Ipv6Icmp: IpNextHeaderProtocol = IpNextHeaderProtocol(58);

    /// No Next Header for IPv6 [RFC2460]
    pub const Ipv6NoNxt: IpNextHeaderProtocol = IpNextHeaderProtocol(59);

    /// Destination Options for IPv6 [RFC2460]
    pub const Ipv6Opts: IpNextHeaderProtocol = IpNextHeaderProtocol(60);

    /// any host internal protocol
    pub const HostInternal: IpNextHeaderProtocol = IpNextHeaderProtocol(61);

    /// CFTP
    pub const Cftp: IpNextHeaderProtocol = IpNextHeaderProtocol(62);

    /// any local network
    pub const LocalNetwork: IpNextHeaderProtocol = IpNextHeaderProtocol(63);

    /// SATNET and Backroom EXPAK
    pub const SatExpak: IpNextHeaderProtocol = IpNextHeaderProtocol(64);

    /// Kryptolan
    pub const Kryptolan: IpNextHeaderProtocol = IpNextHeaderProtocol(65);

    /// MIT Remote Virtual Disk Protocol
    pub const Rvd: IpNextHeaderProtocol = IpNextHeaderProtocol(66);

    /// Internet Pluribus Packet Core
    pub const Ippc: IpNextHeaderProtocol = IpNextHeaderProtocol(67);

    /// any distributed file system
    pub const DistributedFs: IpNextHeaderProtocol = IpNextHeaderProtocol(68);

    /// SATNET Monitoring
    pub const SatMon: IpNextHeaderProtocol = IpNextHeaderProtocol(69);

    /// VISA Protocol
    pub const Visa: IpNextHeaderProtocol = IpNextHeaderProtocol(70);

    /// Internet Packet Core Utility
    pub const Ipcv: IpNextHeaderProtocol = IpNextHeaderProtocol(71);

    /// Computer Protocol Network Executive
    pub const Cpnx: IpNextHeaderProtocol = IpNextHeaderProtocol(72);

    /// Computer Protocol Heart Beat
    pub const Cphb: IpNextHeaderProtocol = IpNextHeaderProtocol(73);

    /// Wang Span Network
    pub const Wsn: IpNextHeaderProtocol = IpNextHeaderProtocol(74);

    /// Packet Video Protocol
    pub const Pvp: IpNextHeaderProtocol = IpNextHeaderProtocol(75);

    /// Backroom SATNET Monitoring
    pub const BrSatMon: IpNextHeaderProtocol = IpNextHeaderProtocol(76);

    /// SUN ND PROTOCOL-Temporary
    pub const SunNd: IpNextHeaderProtocol = IpNextHeaderProtocol(77);

    /// WIDEBAND Monitoring
    pub const WbMon: IpNextHeaderProtocol = IpNextHeaderProtocol(78);

    /// WIDEBAND EXPAK
    pub const WbExpak: IpNextHeaderProtocol = IpNextHeaderProtocol(79);

    /// ISO Internet Protocol
    pub const IsoIp: IpNextHeaderProtocol = IpNextHeaderProtocol(80);

    /// VMTP
    pub const Vmtp: IpNextHeaderProtocol = IpNextHeaderProtocol(81);

    /// SECURE-VMTP
    pub const SecureVmtp: IpNextHeaderProtocol = IpNextHeaderProtocol(82);

    /// VINES
    pub const Vines: IpNextHeaderProtocol = IpNextHeaderProtocol(83);

    /// Transaction Transport Protocol/IP Traffic Manager
    pub const TtpOrIptm: IpNextHeaderProtocol = IpNextHeaderProtocol(84);

    /// NSFNET-IGP
    pub const NsfnetIgp: IpNextHeaderProtocol = IpNextHeaderProtocol(85);

    /// Dissimilar Gateway Protocol
    pub const Dgp: IpNextHeaderProtocol = IpNextHeaderProtocol(86);

    /// TCF
    pub const Tcf: IpNextHeaderProtocol = IpNextHeaderProtocol(87);

    /// EIGRP
    pub const Eigrp: IpNextHeaderProtocol = IpNextHeaderProtocol(88);

    /// OSPFIGP [RFC1583][RFC2328][RFC5340]
    pub const OspfigP: IpNextHeaderProtocol = IpNextHeaderProtocol(89);

    /// Sprite RPC Protocol
    pub const SpriteRpc: IpNextHeaderProtocol = IpNextHeaderProtocol(90);

    /// Locus Address Resolution Protocol
    pub const Larp: IpNextHeaderProtocol = IpNextHeaderProtocol(91);

    /// Multicast Transport Protocol
    pub const Mtp: IpNextHeaderProtocol = IpNextHeaderProtocol(92);

    /// AX.25 Frames
    pub const Ax25: IpNextHeaderProtocol = IpNextHeaderProtocol(93);

    /// IP-within-IP Encapsulation Protocol
    pub const IpIp: IpNextHeaderProtocol = IpNextHeaderProtocol(94);

    /// Mobile Internetworking Control Pro.
    pub const Micp: IpNextHeaderProtocol = IpNextHeaderProtocol(95);

    /// Semaphore Communications Sec. Pro.
    pub const SccSp: IpNextHeaderProtocol = IpNextHeaderProtocol(96);

    /// Ethernet-within-IP Encapsulation [RFC3378]
    pub const Etherip: IpNextHeaderProtocol = IpNextHeaderProtocol(97);

    /// Encapsulation Header [RFC1241]
    pub const Encap: IpNextHeaderProtocol = IpNextHeaderProtocol(98);

    /// any private encryption scheme
    pub const PrivEncryption: IpNextHeaderProtocol = IpNextHeaderProtocol(99);

    /// GMTP
    pub const Gmtp: IpNextHeaderProtocol = IpNextHeaderProtocol(100);

    /// Ipsilon Flow Management Protocol
    pub const Ifmp: IpNextHeaderProtocol = IpNextHeaderProtocol(101);

    /// PNNI over IP
    pub const Pnni: IpNextHeaderProtocol = IpNextHeaderProtocol(102);

    /// Protocol Independent Multicast [RFC4601]
    pub const Pim: IpNextHeaderProtocol = IpNextHeaderProtocol(103);

    /// ARIS
    pub const Aris: IpNextHeaderProtocol = IpNextHeaderProtocol(104);

    /// SCPS
    pub const Scps: IpNextHeaderProtocol = IpNextHeaderProtocol(105);

    /// QNX
    pub const Qnx: IpNextHeaderProtocol = IpNextHeaderProtocol(106);

    /// Active Networks
    pub const AN: IpNextHeaderProtocol = IpNextHeaderProtocol(107);

    /// IP Payload Compression Protocol [RFC2393]
    pub const IpComp: IpNextHeaderProtocol = IpNextHeaderProtocol(108);

    /// Sitara Networks Protocol
    pub const Snp: IpNextHeaderProtocol = IpNextHeaderProtocol(109);

    /// Compaq Peer Protocol
    pub const CompaqPeer: IpNextHeaderProtocol = IpNextHeaderProtocol(110);

    /// IPX in IP
    pub const IpxInIp: IpNextHeaderProtocol = IpNextHeaderProtocol(111);

    /// Virtual Router Redundancy Protocol [RFC5798]
    pub const Vrrp: IpNextHeaderProtocol = IpNextHeaderProtocol(112);

    /// PGM Reliable Transport Protocol
    pub const Pgm: IpNextHeaderProtocol = IpNextHeaderProtocol(113);

    /// any 0-hop protocol
    pub const ZeroHop: IpNextHeaderProtocol = IpNextHeaderProtocol(114);

    /// Layer Two Tunneling Protocol [RFC3931]
    pub const L2tp: IpNextHeaderProtocol = IpNextHeaderProtocol(115);

    /// D-II Data Exchange (DDX)
    pub const Ddx: IpNextHeaderProtocol = IpNextHeaderProtocol(116);

    /// Interactive Agent Transfer Protocol
    pub const Iatp: IpNextHeaderProtocol = IpNextHeaderProtocol(117);

    /// Schedule Transfer Protocol
    pub const Stp: IpNextHeaderProtocol = IpNextHeaderProtocol(118);

    /// SpectraLink Radio Protocol
    pub const Srp: IpNextHeaderProtocol = IpNextHeaderProtocol(119);

    /// UTI
    pub const Uti: IpNextHeaderProtocol = IpNextHeaderProtocol(120);

    /// Simple Message Protocol
    pub const Smp: IpNextHeaderProtocol = IpNextHeaderProtocol(121);

    /// Simple Multicast Protocol
    pub const Sm: IpNextHeaderProtocol = IpNextHeaderProtocol(122);

    /// Performance Transparency Protocol
    pub const Ptp: IpNextHeaderProtocol = IpNextHeaderProtocol(123);

    ///
    pub const IsisOverIpv4: IpNextHeaderProtocol = IpNextHeaderProtocol(124);

    ///
    pub const Fire: IpNextHeaderProtocol = IpNextHeaderProtocol(125);

    /// Combat Radio Transport Protocol
    pub const Crtp: IpNextHeaderProtocol = IpNextHeaderProtocol(126);

    /// Combat Radio User Datagram
    pub const Crudp: IpNextHeaderProtocol = IpNextHeaderProtocol(127);

    ///
    pub const Sscopmce: IpNextHeaderProtocol = IpNextHeaderProtocol(128);

    ///
    pub const Iplt: IpNextHeaderProtocol = IpNextHeaderProtocol(129);

    /// Secure Packet Shield
    pub const Sps: IpNextHeaderProtocol = IpNextHeaderProtocol(130);

    /// Private IP Encapsulation within IP
    pub const Pipe: IpNextHeaderProtocol = IpNextHeaderProtocol(131);

    /// Stream Control Transmission Protocol
    pub const Sctp: IpNextHeaderProtocol = IpNextHeaderProtocol(132);

    /// Fibre Channel [RFC6172]
    pub const Fc: IpNextHeaderProtocol = IpNextHeaderProtocol(133);

    /// [RFC3175]
    pub const RsvpE2eIgnore: IpNextHeaderProtocol = IpNextHeaderProtocol(134);

    /// [RFC6275]
    pub const MobilityHeader: IpNextHeaderProtocol = IpNextHeaderProtocol(135);

    /// [RFC3828]
    pub const UdpLite: IpNextHeaderProtocol = IpNextHeaderProtocol(136);

    /// [RFC4023]
    pub const MplsInIp: IpNextHeaderProtocol = IpNextHeaderProtocol(137);

    /// MANET Protocols [RFC5498]
    pub const Manet: IpNextHeaderProtocol = IpNextHeaderProtocol(138);

    /// Host Identity Protocol [RFC5201]
    pub const Hip: IpNextHeaderProtocol = IpNextHeaderProtocol(139);

    /// Shim6 Protocol [RFC5533]
    pub const Shim6: IpNextHeaderProtocol = IpNextHeaderProtocol(140);

    /// Wrapped Encapsulating Security Payload [RFC5840]
    pub const Wesp: IpNextHeaderProtocol = IpNextHeaderProtocol(141);

    /// Robust Header Compression [RFC5858]
    pub const Rohc: IpNextHeaderProtocol = IpNextHeaderProtocol(142);

    /// Use for experimentation and testing [RFC3692]
    pub const Test1: IpNextHeaderProtocol = IpNextHeaderProtocol(253);

    /// Use for experimentation and testing [RFC3692]
    pub const Test2: IpNextHeaderProtocol = IpNextHeaderProtocol(254);

    ///
    pub const Reserved: IpNextHeaderProtocol = IpNextHeaderProtocol(255);

}

/// Represents an IPv4 next level protocol, or an IPv6 next header protocol,
/// see `IpNextHeaderProtocols` for a list of values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpNextHeaderProtocol(pub u8);

impl IpNextHeaderProtocol {
    /// Create a new IpNextHeaderProtocol
    pub fn new(value: u8) -> IpNextHeaderProtocol {
        IpNextHeaderProtocol(value)
    }
}

impl PrimitiveValues for IpNextHeaderProtocol {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

impl fmt::Display for IpNextHeaderProtocol       {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            &IpNextHeaderProtocols::Hopopt => "Hopopt", // 0
            &IpNextHeaderProtocols::Icmp => "Icmp", // 1
            &IpNextHeaderProtocols::Igmp => "Igmp", // 2
            &IpNextHeaderProtocols::Ggp => "Ggp", // 3
            &IpNextHeaderProtocols::Ipv4 => "Ipv4", // 4
            &IpNextHeaderProtocols::St => "St", // 5
            &IpNextHeaderProtocols::Tcp => "Tcp", // 6
            &IpNextHeaderProtocols::Cbt => "Cbt", // 7
            &IpNextHeaderProtocols::Egp => "Egp", // 8
            &IpNextHeaderProtocols::Igp => "Igp", // 9
            &IpNextHeaderProtocols::BbnRccMon => "BbnRccMon", // 10
            &IpNextHeaderProtocols::NvpII => "NvpII", // 11
            &IpNextHeaderProtocols::Pup => "Pup", // 12
            &IpNextHeaderProtocols::Argus => "Argus", // 13
            &IpNextHeaderProtocols::Emcon => "Emcon", // 14
            &IpNextHeaderProtocols::Xnet => "Xnet", // 15
            &IpNextHeaderProtocols::Chaos => "Chaos", // 16
            &IpNextHeaderProtocols::Udp => "Udp", // 17
            &IpNextHeaderProtocols::Mux => "Mux", // 18
            &IpNextHeaderProtocols::DcnMeas => "DcnMeas", // 19
            &IpNextHeaderProtocols::Hmp => "Hmp", // 20
            &IpNextHeaderProtocols::Prm => "Prm", // 21
            &IpNextHeaderProtocols::XnsIdp => "XnsIdp", // 22
            &IpNextHeaderProtocols::Trunk1 => "Trunk1", // 23
            &IpNextHeaderProtocols::Trunk2 => "Trunk2", // 24
            &IpNextHeaderProtocols::Leaf1 => "Leaf1", // 25
            &IpNextHeaderProtocols::Leaf2 => "Leaf2", // 26
            &IpNextHeaderProtocols::Rdp => "Rdp", // 27
            &IpNextHeaderProtocols::Irtp => "Irtp", // 28
            &IpNextHeaderProtocols::IsoTp4 => "IsoTp4", // 29
            &IpNextHeaderProtocols::Netblt => "Netblt", // 30
            &IpNextHeaderProtocols::MfeNsp => "MfeNsp", // 31
            &IpNextHeaderProtocols::MeritInp => "MeritInp", // 32
            &IpNextHeaderProtocols::Dccp => "Dccp", // 33
            &IpNextHeaderProtocols::ThreePc => "ThreePc", // 34
            &IpNextHeaderProtocols::Idpr => "Idpr", // 35
            &IpNextHeaderProtocols::Xtp => "Xtp", // 36
            &IpNextHeaderProtocols::Ddp => "Ddp", // 37
            &IpNextHeaderProtocols::IdprCmtp => "IdprCmtp", // 38
            &IpNextHeaderProtocols::TpPlusPlus => "TpPlusPlus", // 39
            &IpNextHeaderProtocols::Il => "Il", // 40
            &IpNextHeaderProtocols::Ipv6 => "Ipv6", // 41
            &IpNextHeaderProtocols::Sdrp => "Sdrp", // 42
            &IpNextHeaderProtocols::Ipv6Route => "Ipv6Route", // 43
            &IpNextHeaderProtocols::Ipv6Frag => "Ipv6Frag", // 44
            &IpNextHeaderProtocols::Idrp => "Idrp", // 45
            &IpNextHeaderProtocols::Rsvp => "Rsvp", // 46
            &IpNextHeaderProtocols::Gre => "Gre", // 47
            &IpNextHeaderProtocols::Dsr => "Dsr", // 48
            &IpNextHeaderProtocols::Bna => "Bna", // 49
            &IpNextHeaderProtocols::Esp => "Esp", // 50
            &IpNextHeaderProtocols::Ah => "Ah", // 51
            &IpNextHeaderProtocols::INlsp => "INlsp", // 52
            &IpNextHeaderProtocols::Swipe => "Swipe", // 53
            &IpNextHeaderProtocols::Narp => "Narp", // 54
            &IpNextHeaderProtocols::Mobile => "Mobile", // 55
            &IpNextHeaderProtocols::Tlsp => "Tlsp", // 56
            &IpNextHeaderProtocols::Skip => "Skip", // 57
            &IpNextHeaderProtocols::Ipv6Icmp => "Ipv6Icmp", // 58
            &IpNextHeaderProtocols::Ipv6NoNxt => "Ipv6NoNxt", // 59
            &IpNextHeaderProtocols::Ipv6Opts => "Ipv6Opts", // 60
            &IpNextHeaderProtocols::HostInternal => "HostInternal", // 61
            &IpNextHeaderProtocols::Cftp => "Cftp", // 62
            &IpNextHeaderProtocols::LocalNetwork => "LocalNetwork", // 63
            &IpNextHeaderProtocols::SatExpak => "SatExpak", // 64
            &IpNextHeaderProtocols::Kryptolan => "Kryptolan", // 65
            &IpNextHeaderProtocols::Rvd => "Rvd", // 66
            &IpNextHeaderProtocols::Ippc => "Ippc", // 67
            &IpNextHeaderProtocols::DistributedFs => "DistributedFs", // 68
            &IpNextHeaderProtocols::SatMon => "SatMon", // 69
            &IpNextHeaderProtocols::Visa => "Visa", // 70
            &IpNextHeaderProtocols::Ipcv => "Ipcv", // 71
            &IpNextHeaderProtocols::Cpnx => "Cpnx", // 72
            &IpNextHeaderProtocols::Cphb => "Cphb", // 73
            &IpNextHeaderProtocols::Wsn => "Wsn", // 74
            &IpNextHeaderProtocols::Pvp => "Pvp", // 75
            &IpNextHeaderProtocols::BrSatMon => "BrSatMon", // 76
            &IpNextHeaderProtocols::SunNd => "SunNd", // 77
            &IpNextHeaderProtocols::WbMon => "WbMon", // 78
            &IpNextHeaderProtocols::WbExpak => "WbExpak", // 79
            &IpNextHeaderProtocols::IsoIp => "IsoIp", // 80
            &IpNextHeaderProtocols::Vmtp => "Vmtp", // 81
            &IpNextHeaderProtocols::SecureVmtp => "SecureVmtp", // 82
            &IpNextHeaderProtocols::Vines => "Vines", // 83
            &IpNextHeaderProtocols::TtpOrIptm => "TtpOrIptm", // 84
            &IpNextHeaderProtocols::NsfnetIgp => "NsfnetIgp", // 85
            &IpNextHeaderProtocols::Dgp => "Dgp", // 86
            &IpNextHeaderProtocols::Tcf => "Tcf", // 87
            &IpNextHeaderProtocols::Eigrp => "Eigrp", // 88
            &IpNextHeaderProtocols::OspfigP => "OspfigP", // 89
            &IpNextHeaderProtocols::SpriteRpc => "SpriteRpc", // 90
            &IpNextHeaderProtocols::Larp => "Larp", // 91
            &IpNextHeaderProtocols::Mtp => "Mtp", // 92
            &IpNextHeaderProtocols::Ax25 => "Ax25", // 93
            &IpNextHeaderProtocols::IpIp => "IpIp", // 94
            &IpNextHeaderProtocols::Micp => "Micp", // 95
            &IpNextHeaderProtocols::SccSp => "SccSp", // 96
            &IpNextHeaderProtocols::Etherip => "Etherip", // 97
            &IpNextHeaderProtocols::Encap => "Encap", // 98
            &IpNextHeaderProtocols::PrivEncryption => "PrivEncryption", // 99
            &IpNextHeaderProtocols::Gmtp => "Gmtp", // 100
            &IpNextHeaderProtocols::Ifmp => "Ifmp", // 101
            &IpNextHeaderProtocols::Pnni => "Pnni", // 102
            &IpNextHeaderProtocols::Pim => "Pim", // 103
            &IpNextHeaderProtocols::Aris => "Aris", // 104
            &IpNextHeaderProtocols::Scps => "Scps", // 105
            &IpNextHeaderProtocols::Qnx => "Qnx", // 106
            &IpNextHeaderProtocols::AN => "AN", // 107
            &IpNextHeaderProtocols::IpComp => "IpComp", // 108
            &IpNextHeaderProtocols::Snp => "Snp", // 109
            &IpNextHeaderProtocols::CompaqPeer => "CompaqPeer", // 110
            &IpNextHeaderProtocols::IpxInIp => "IpxInIp", // 111
            &IpNextHeaderProtocols::Vrrp => "Vrrp", // 112
            &IpNextHeaderProtocols::Pgm => "Pgm", // 113
            &IpNextHeaderProtocols::ZeroHop => "ZeroHop", // 114
            &IpNextHeaderProtocols::L2tp => "L2tp", // 115
            &IpNextHeaderProtocols::Ddx => "Ddx", // 116
            &IpNextHeaderProtocols::Iatp => "Iatp", // 117
            &IpNextHeaderProtocols::Stp => "Stp", // 118
            &IpNextHeaderProtocols::Srp => "Srp", // 119
            &IpNextHeaderProtocols::Uti => "Uti", // 120
            &IpNextHeaderProtocols::Smp => "Smp", // 121
            &IpNextHeaderProtocols::Sm => "Sm", // 122
            &IpNextHeaderProtocols::Ptp => "Ptp", // 123
            &IpNextHeaderProtocols::IsisOverIpv4 => "IsisOverIpv4", // 124
            &IpNextHeaderProtocols::Fire => "Fire", // 125
            &IpNextHeaderProtocols::Crtp => "Crtp", // 126
            &IpNextHeaderProtocols::Crudp => "Crudp", // 127
            &IpNextHeaderProtocols::Sscopmce => "Sscopmce", // 128
            &IpNextHeaderProtocols::Iplt => "Iplt", // 129
            &IpNextHeaderProtocols::Sps => "Sps", // 130
            &IpNextHeaderProtocols::Pipe => "Pipe", // 131
            &IpNextHeaderProtocols::Sctp => "Sctp", // 132
            &IpNextHeaderProtocols::Fc => "Fc", // 133
            &IpNextHeaderProtocols::RsvpE2eIgnore => "RsvpE2eIgnore", // 134
            &IpNextHeaderProtocols::MobilityHeader => "MobilityHeader", // 135
            &IpNextHeaderProtocols::UdpLite => "UdpLite", // 136
            &IpNextHeaderProtocols::MplsInIp => "MplsInIp", // 137
            &IpNextHeaderProtocols::Manet => "Manet", // 138
            &IpNextHeaderProtocols::Hip => "Hip", // 139
            &IpNextHeaderProtocols::Shim6 => "Shim6", // 140
            &IpNextHeaderProtocols::Wesp => "Wesp", // 141
            &IpNextHeaderProtocols::Rohc => "Rohc", // 142
            &IpNextHeaderProtocols::Test1 => "Test1", // 253
            &IpNextHeaderProtocols::Test2 => "Test2", // 254*/
            &IpNextHeaderProtocols::Reserved => "Reserved", // 255
            _                          => "unknown"
        })
    }
}