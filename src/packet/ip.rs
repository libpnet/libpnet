// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Defines the type and constants for IP next header/next level protocol fields.

#[allow(non_snake_case)]

/// Protocol numbers as defined at:
/// http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
/// Above protocol numbers last updated: 2014-01-16
/// These values should be used in either the IPv4 Next Level Protocol field
/// or the IPv6 Next Header field.
pub mod IpNextHeaderProtocols {
    use super::IpNextHeaderProtocol;

    /// IPv6 Hop-by-Hop Option [RFC2460]
    pub static Hopopt: IpNextHeaderProtocol         = IpNextHeaderProtocol(0);

    /// Internet Control Message [RFC792]
    pub static Icmp: IpNextHeaderProtocol           = IpNextHeaderProtocol(1);

    /// Internet Group Management [RFC1112]
    pub static Igmp: IpNextHeaderProtocol           = IpNextHeaderProtocol(2);

    /// Gateway-to-Gateway [RFC823]
    pub static Ggp: IpNextHeaderProtocol            = IpNextHeaderProtocol(3);

    /// IPv4 encapsulation [RFC2003]
    pub static Ipv4: IpNextHeaderProtocol           = IpNextHeaderProtocol(4);

    /// Stream [RFC1190][RFC1819]
    pub static St: IpNextHeaderProtocol             = IpNextHeaderProtocol(5);

    /// Transmission Control [RFC793]
    pub static Tcp: IpNextHeaderProtocol            = IpNextHeaderProtocol(6);

    /// CBT
    pub static Cbt: IpNextHeaderProtocol            = IpNextHeaderProtocol(7);

    /// Exterior Gateway Protocol [RFC888]
    pub static Egp: IpNextHeaderProtocol            = IpNextHeaderProtocol(8);

    /// any private interior gateway (used by Cisco for their IGRP)
    pub static Igp: IpNextHeaderProtocol            = IpNextHeaderProtocol(9);

    /// BBN RCC Monitoring
    pub static BbnRccMon: IpNextHeaderProtocol      = IpNextHeaderProtocol(10);

    /// Network Voice Protocol [RFC741]
    pub static NvpII: IpNextHeaderProtocol          = IpNextHeaderProtocol(11);

    /// PUP
    pub static Pup: IpNextHeaderProtocol            = IpNextHeaderProtocol(12);

    /// ARGUS
    pub static Argus: IpNextHeaderProtocol          = IpNextHeaderProtocol(13);

    /// EMCON
    pub static Emcon: IpNextHeaderProtocol          = IpNextHeaderProtocol(14);

    /// Cross Net Debugger
    pub static Xnet: IpNextHeaderProtocol           = IpNextHeaderProtocol(15);

    /// Chaos
    pub static Chaos: IpNextHeaderProtocol          = IpNextHeaderProtocol(16);

    /// User Datagram [RFC768]
    pub static Udp: IpNextHeaderProtocol            = IpNextHeaderProtocol(17);

    /// Multiplexing
    pub static Mux: IpNextHeaderProtocol            = IpNextHeaderProtocol(18);

    /// DCN Measurement Subsystems
    pub static DcnMeas: IpNextHeaderProtocol        = IpNextHeaderProtocol(19);

    /// Host Monitoring [RFC869]
    pub static Hmp: IpNextHeaderProtocol            = IpNextHeaderProtocol(20);

    /// Packet Radio Measurement
    pub static Prm: IpNextHeaderProtocol            = IpNextHeaderProtocol(21);

    /// XEROX NS IDP
    pub static XnsIdp: IpNextHeaderProtocol         = IpNextHeaderProtocol(22);

    /// Trunk-1
    pub static Trunk1: IpNextHeaderProtocol         = IpNextHeaderProtocol(23);

    /// Trunk-2
    pub static Trunk2: IpNextHeaderProtocol         = IpNextHeaderProtocol(24);

    /// Leaf-1
    pub static Leaf1: IpNextHeaderProtocol          = IpNextHeaderProtocol(25);

    /// Leaf-2
    pub static Leaf2: IpNextHeaderProtocol          = IpNextHeaderProtocol(26);

    /// Reliable Data Protocol [RFC908]
    pub static Rdp: IpNextHeaderProtocol            = IpNextHeaderProtocol(27);

    /// Internet Reliable Transaction [RFC938]
    pub static Irtp: IpNextHeaderProtocol           = IpNextHeaderProtocol(28);

    /// ISO Transport Protocol Class 4 [RFC905]
    pub static IsoTp4: IpNextHeaderProtocol         = IpNextHeaderProtocol(29);

    /// Bulk Data Transfer Protocol [RFC969]
    pub static Netblt: IpNextHeaderProtocol         = IpNextHeaderProtocol(30);

    /// MFE Network Services Protocol
    pub static MfeNsp: IpNextHeaderProtocol         = IpNextHeaderProtocol(31);

    /// MERIT Internodal Protocol
    pub static MeritInp: IpNextHeaderProtocol       = IpNextHeaderProtocol(32);

    /// Datagram Congestion Control Protocol [RFC4340]
    pub static Dccp: IpNextHeaderProtocol           = IpNextHeaderProtocol(33);

    /// Third Party Connect Protocol
    pub static ThreePc: IpNextHeaderProtocol        = IpNextHeaderProtocol(34);

    /// Inter-Domain Policy Routing Protocol
    pub static Idpr: IpNextHeaderProtocol           = IpNextHeaderProtocol(35);

    /// XTP
    pub static Xtp: IpNextHeaderProtocol            = IpNextHeaderProtocol(36);

    /// Datagram Delivery Protocol
    pub static Ddp: IpNextHeaderProtocol            = IpNextHeaderProtocol(37);

    /// IDPR Control Message Transport Proto
    pub static IdprCmtp: IpNextHeaderProtocol       = IpNextHeaderProtocol(38);

    /// TP++ Transport Protocol
    pub static TpPlusPlus: IpNextHeaderProtocol     = IpNextHeaderProtocol(39);

    /// IL Transport Protocol
    pub static Il: IpNextHeaderProtocol             = IpNextHeaderProtocol(40);

    /// IPv6 encapsulation [RFC2473]
    pub static Ipv6: IpNextHeaderProtocol           = IpNextHeaderProtocol(41);

    /// Source Demand Routing Protocol
    pub static Sdrp: IpNextHeaderProtocol           = IpNextHeaderProtocol(42);

    /// Routing Header for IPv6
    pub static Ipv6Route: IpNextHeaderProtocol      = IpNextHeaderProtocol(43);

    /// Fragment Header for IPv6
    pub static Ipv6Frag: IpNextHeaderProtocol       = IpNextHeaderProtocol(44);

    /// Inter-Domain Routing Protocol
    pub static Idrp: IpNextHeaderProtocol           = IpNextHeaderProtocol(45);

    /// Reservation Protocol [RFC2205][RFC3209]
    pub static Rsvp: IpNextHeaderProtocol           = IpNextHeaderProtocol(46);

    /// Generic Routing Encapsulation [RFC1701]
    pub static Gre: IpNextHeaderProtocol            = IpNextHeaderProtocol(47);

    /// Dynamic Source Routing Protocol [RFC4728]
    pub static Dsr: IpNextHeaderProtocol            = IpNextHeaderProtocol(48);

    /// BNA
    pub static Bna: IpNextHeaderProtocol            = IpNextHeaderProtocol(49);

    /// Encap Security Payload [RFC4303]
    pub static Esp: IpNextHeaderProtocol            = IpNextHeaderProtocol(50);

    /// Authentication Header [RFC4302]
    pub static Ah: IpNextHeaderProtocol             = IpNextHeaderProtocol(51);

    /// Integrated Net Layer Security TUBA
    pub static INlsp: IpNextHeaderProtocol          = IpNextHeaderProtocol(52);

    /// IP with Encryption
    pub static Swipe: IpNextHeaderProtocol          = IpNextHeaderProtocol(53);

    /// NBMA Address Resolution Protocol [RFC1735]
    pub static Narp: IpNextHeaderProtocol           = IpNextHeaderProtocol(54);

    /// IP Mobility
    pub static Mobile: IpNextHeaderProtocol         = IpNextHeaderProtocol(55);

    /// Transport Layer Security Protocol using Kryptonet key management
    pub static Tlsp: IpNextHeaderProtocol           = IpNextHeaderProtocol(56);

    /// SKIP
    pub static Skip: IpNextHeaderProtocol           = IpNextHeaderProtocol(57);

    /// ICMP for IPv6 [RFC2460]
    pub static Ipv6Icmp: IpNextHeaderProtocol       = IpNextHeaderProtocol(58);

    /// No Next Header for IPv6 [RFC2460]
    pub static Ipv6NoNxt: IpNextHeaderProtocol      = IpNextHeaderProtocol(59);

    /// Destination Options for IPv6 [RFC2460]
    pub static Ipv6Opts: IpNextHeaderProtocol       = IpNextHeaderProtocol(60);

    /// any host internal protocol
    pub static HostInternal: IpNextHeaderProtocol   = IpNextHeaderProtocol(61);

    /// CFTP
    pub static Cftp: IpNextHeaderProtocol           = IpNextHeaderProtocol(62);

    /// any local network
    pub static LocalNetwork: IpNextHeaderProtocol   = IpNextHeaderProtocol(63);

    /// SATNET and Backroom EXPAK
    pub static SatExpak: IpNextHeaderProtocol       = IpNextHeaderProtocol(64);

    /// Kryptolan
    pub static Kryptolan: IpNextHeaderProtocol      = IpNextHeaderProtocol(65);

    /// MIT Remote Virtual Disk Protocol
    pub static Rvd: IpNextHeaderProtocol            = IpNextHeaderProtocol(66);

    /// Internet Pluribus Packet Core
    pub static Ippc: IpNextHeaderProtocol           = IpNextHeaderProtocol(67);

    /// any distributed file system
    pub static DistributedFs: IpNextHeaderProtocol  = IpNextHeaderProtocol(68);

    /// SATNET Monitoring
    pub static SatMon: IpNextHeaderProtocol         = IpNextHeaderProtocol(69);

    /// VISA Protocol
    pub static Visa: IpNextHeaderProtocol           = IpNextHeaderProtocol(70);

    /// Internet Packet Core Utility
    pub static Ipcv: IpNextHeaderProtocol           = IpNextHeaderProtocol(71);

    /// Computer Protocol Network Executive
    pub static Cpnx: IpNextHeaderProtocol           = IpNextHeaderProtocol(72);

    /// Computer Protocol Heart Beat
    pub static Cphb: IpNextHeaderProtocol           = IpNextHeaderProtocol(73);

    /// Wang Span Network
    pub static Wsn: IpNextHeaderProtocol            = IpNextHeaderProtocol(74);

    /// Packet Video Protocol
    pub static Pvp: IpNextHeaderProtocol            = IpNextHeaderProtocol(75);

    /// Backroom SATNET Monitoring
    pub static BrSatMon: IpNextHeaderProtocol       = IpNextHeaderProtocol(76);

    /// SUN ND PROTOCOL-Temporary
    pub static SunNd: IpNextHeaderProtocol          = IpNextHeaderProtocol(77);

    /// WIDEBAND Monitoring
    pub static WbMon: IpNextHeaderProtocol          = IpNextHeaderProtocol(78);

    /// WIDEBAND EXPAK
    pub static WbExpak: IpNextHeaderProtocol        = IpNextHeaderProtocol(79);

    /// ISO Internet Protocol
    pub static IsoIp: IpNextHeaderProtocol          = IpNextHeaderProtocol(80);

    /// VMTP
    pub static Vmtp: IpNextHeaderProtocol           = IpNextHeaderProtocol(81);

    /// SECURE-VMTP
    pub static SecureVmtp: IpNextHeaderProtocol     = IpNextHeaderProtocol(82);

    /// VINES
    pub static Vines: IpNextHeaderProtocol          = IpNextHeaderProtocol(83);

    /// Transaction Transport Protocol/IP Traffic Manager
    pub static TtpOrIptm: IpNextHeaderProtocol      = IpNextHeaderProtocol(84);

    /// NSFNET-IGP
    pub static NsfnetIgp: IpNextHeaderProtocol      = IpNextHeaderProtocol(85);

    /// Dissimilar Gateway Protocol
    pub static Dgp: IpNextHeaderProtocol            = IpNextHeaderProtocol(86);

    /// TCF
    pub static Tcf: IpNextHeaderProtocol            = IpNextHeaderProtocol(87);

    /// EIGRP
    pub static Eigrp: IpNextHeaderProtocol          = IpNextHeaderProtocol(88);

    /// OSPFIGP [RFC1583][RFC2328][RFC5340]
    pub static OspfigP: IpNextHeaderProtocol        = IpNextHeaderProtocol(89);

    /// Sprite RPC Protocol
    pub static SpriteRpc: IpNextHeaderProtocol      = IpNextHeaderProtocol(90);

    /// Locus Address Resolution Protocol
    pub static Larp: IpNextHeaderProtocol           = IpNextHeaderProtocol(91);

    /// Multicast Transport Protocol
    pub static Mtp: IpNextHeaderProtocol            = IpNextHeaderProtocol(92);

    /// AX.25 Frames
    pub static Ax25: IpNextHeaderProtocol           = IpNextHeaderProtocol(93);

    /// IP-within-IP Encapsulation Protocol
    pub static IpIp: IpNextHeaderProtocol           = IpNextHeaderProtocol(94);

    /// Mobile Internetworking Control Pro.
    pub static Micp: IpNextHeaderProtocol           = IpNextHeaderProtocol(95);

    /// Semaphore Communications Sec. Pro.
    pub static SccSp: IpNextHeaderProtocol          = IpNextHeaderProtocol(96);

    /// Ethernet-within-IP Encapsulation [RFC3378]
    pub static Etherip: IpNextHeaderProtocol        = IpNextHeaderProtocol(97);

    /// Encapsulation Header [RFC1241]
    pub static Encap: IpNextHeaderProtocol          = IpNextHeaderProtocol(98);

    /// any private encryption scheme
    pub static PrivEncryption: IpNextHeaderProtocol = IpNextHeaderProtocol(99);

    /// GMTP
    pub static Gmtp: IpNextHeaderProtocol           = IpNextHeaderProtocol(100);

    /// Ipsilon Flow Management Protocol
    pub static Ifmp: IpNextHeaderProtocol           = IpNextHeaderProtocol(101);

    /// PNNI over IP
    pub static Pnni: IpNextHeaderProtocol           = IpNextHeaderProtocol(102);

    /// Protocol Independent Multicast [RFC4601]
    pub static Pim: IpNextHeaderProtocol            = IpNextHeaderProtocol(103);

    /// ARIS
    pub static Aris: IpNextHeaderProtocol           = IpNextHeaderProtocol(104);

    /// SCPS
    pub static Scps: IpNextHeaderProtocol           = IpNextHeaderProtocol(105);

    /// QNX
    pub static Qnx: IpNextHeaderProtocol            = IpNextHeaderProtocol(106);

    /// Active Networks
    pub static AN: IpNextHeaderProtocol             = IpNextHeaderProtocol(107);

    /// IP Payload Compression Protocol [RFC2393]
    pub static IpComp: IpNextHeaderProtocol         = IpNextHeaderProtocol(108);

    /// Sitara Networks Protocol
    pub static Snp: IpNextHeaderProtocol            = IpNextHeaderProtocol(109);

    /// Compaq Peer Protocol
    pub static CompaqPeer: IpNextHeaderProtocol     = IpNextHeaderProtocol(110);

    /// IPX in IP
    pub static IpxInIp: IpNextHeaderProtocol        = IpNextHeaderProtocol(111);

    /// Virtual Router Redundancy Protocol [RFC5798]
    pub static Vrrp: IpNextHeaderProtocol           = IpNextHeaderProtocol(112);

    /// PGM Reliable Transport Protocol
    pub static Pgm: IpNextHeaderProtocol            = IpNextHeaderProtocol(113);

    /// any 0-hop protocol
    pub static ZeroHop: IpNextHeaderProtocol        = IpNextHeaderProtocol(114);

    /// Layer Two Tunneling Protocol [RFC3931]
    pub static L2tp: IpNextHeaderProtocol           = IpNextHeaderProtocol(115);

    /// D-II Data Exchange (DDX)
    pub static Ddx: IpNextHeaderProtocol            = IpNextHeaderProtocol(116);

    /// Interactive Agent Transfer Protocol
    pub static Iatp: IpNextHeaderProtocol           = IpNextHeaderProtocol(117);

    /// Schedule Transfer Protocol
    pub static Stp: IpNextHeaderProtocol            = IpNextHeaderProtocol(118);

    /// SpectraLink Radio Protocol
    pub static Srp: IpNextHeaderProtocol            = IpNextHeaderProtocol(119);

    /// UTI
    pub static Uti: IpNextHeaderProtocol            = IpNextHeaderProtocol(120);

    /// Simple Message Protocol
    pub static Smp: IpNextHeaderProtocol            = IpNextHeaderProtocol(121);

    /// Simple Multicast Protocol
    pub static Sm: IpNextHeaderProtocol             = IpNextHeaderProtocol(122);

    /// Performance Transparency Protocol
    pub static Ptp: IpNextHeaderProtocol            = IpNextHeaderProtocol(123);

    ///
    pub static IsisOverIpv4: IpNextHeaderProtocol   = IpNextHeaderProtocol(124);

    ///
    pub static Fire: IpNextHeaderProtocol           = IpNextHeaderProtocol(125);

    /// Combat Radio Transport Protocol
    pub static Crtp: IpNextHeaderProtocol           = IpNextHeaderProtocol(126);

    /// Combat Radio User Datagram
    pub static Crudp: IpNextHeaderProtocol          = IpNextHeaderProtocol(127);

    ///
    pub static Sscopmce: IpNextHeaderProtocol       = IpNextHeaderProtocol(128);

    ///
    pub static Iplt: IpNextHeaderProtocol           = IpNextHeaderProtocol(129);

    /// Secure Packet Shield
    pub static Sps: IpNextHeaderProtocol            = IpNextHeaderProtocol(130);

    /// Private IP Encapsulation within IP
    pub static Pipe: IpNextHeaderProtocol           = IpNextHeaderProtocol(131);

    /// Stream Control Transmission Protocol
    pub static Sctp: IpNextHeaderProtocol           = IpNextHeaderProtocol(132);

    /// Fibre Channel [RFC6172]
    pub static Fc: IpNextHeaderProtocol             = IpNextHeaderProtocol(133);

    /// [RFC3175]
    pub static RsvpE2eIgnore: IpNextHeaderProtocol  = IpNextHeaderProtocol(134);

    /// [RFC6275]
    pub static MobilityHeader: IpNextHeaderProtocol = IpNextHeaderProtocol(135);

    /// [RFC3828]
    pub static UdpLite: IpNextHeaderProtocol        = IpNextHeaderProtocol(136);

    /// [RFC4023]
    pub static MplsInIp: IpNextHeaderProtocol       = IpNextHeaderProtocol(137);

    /// MANET Protocols [RFC5498]
    pub static Manet: IpNextHeaderProtocol          = IpNextHeaderProtocol(138);

    /// Host Identity Protocol [RFC5201]
    pub static Hip: IpNextHeaderProtocol            = IpNextHeaderProtocol(139);

    /// Shim6 Protocol [RFC5533]
    pub static Shim6: IpNextHeaderProtocol          = IpNextHeaderProtocol(140);

    /// Wrapped Encapsulating Security Payload [RFC5840]
    pub static Wesp: IpNextHeaderProtocol           = IpNextHeaderProtocol(141);

    /// Robust Header Compression [RFC5858]
    pub static Rohc: IpNextHeaderProtocol           = IpNextHeaderProtocol(142);

    /// Use for experimentation and testing [RFC3692]
    pub static Test1: IpNextHeaderProtocol          = IpNextHeaderProtocol(253);

    /// Use for experimentation and testing [RFC3692]
    pub static Test2: IpNextHeaderProtocol          = IpNextHeaderProtocol(254);

    ///
    pub static Reserved: IpNextHeaderProtocol       = IpNextHeaderProtocol(255);

}

/// Represents an IPv4 next level protocol, or an IPv6 next header protocol,
/// see `IpNextHeaderProtocols` for a list of values.
#[deriving(Show, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpNextHeaderProtocol(pub u8);

