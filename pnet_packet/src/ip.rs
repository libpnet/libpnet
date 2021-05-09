// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
use PrimitiveValues;

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

/// Build Const and implements Display and FromStr from this list of protocols
/// Protocol numbers as defined at:
/// http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
/// Above protocol numbers last updated: 2014-01-16
/// These values should be used in either the IPv4 Next Level Protocol field
/// or the IPv6 Next Header field.
/// NOTE Everything here is pretending to be an enum, but with namespacing by
///      default, so we allow breaking style guidelines.
macro_rules! define_ip_next_header_protocols {
    (
        @display_impl
        { $($result:tt)* }
        { }
    ) => {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match *self {
                $($result)*
                _ => "unknown",
            })
        }
    };

    (
        @display_impl
        { $($result:tt)* }
        {
            { #[deprecated(note = $deprecated:expr)] $name:ident }
            $($rest:tt)*
        }
    ) => {
        define_ip_next_header_protocols! {
            @display_impl
            { $($result)* }
            { $($rest)* }
        }
    };

    (
        @display_impl
        { $($result:tt)* }
        {
            { $name:ident }
            $($rest:tt)*
        }
    ) => {
        define_ip_next_header_protocols! {
            @display_impl
            { $($result)* IpNextHeaderProtocols::$name => stringify!($name), }
            { $($rest)* }
        }
    };

    ($(
        $(#[deprecated(note = $deprecated:expr)])?
        $(#[doc = $doc:expr])?
        $name:ident = $value:expr,
    )*) => {
        #[allow(
            non_snake_case,
            non_upper_case_globals,
        )]
        pub mod IpNextHeaderProtocols {
            $(
                $(#[deprecated(note = $deprecated)])?
                $(#[doc = $doc])?
                pub const $name: super::IpNextHeaderProtocol = super::IpNextHeaderProtocol($value);
            )*
        }

        impl std::fmt::Display for IpNextHeaderProtocol {
            define_ip_next_header_protocols! {
                @display_impl
                { }
                { $({ $(#[deprecated(note = $deprecated)])? $name })* }
            }
        }

        impl std::str::FromStr for IpNextHeaderProtocol {
            type Err = ();

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                #[allow(deprecated)]
                Ok(match s {
                    $(
                        stringify!($name) => IpNextHeaderProtocols::$name,
                    )*
                    _ => return Err(()),
                })
            }
        }
    };
}

define_ip_next_header_protocols! {
    /// IPv6 Hop-by-Hop Option [RFC2460]
    Hopopt = 0,

    /// Internet Control Message [RFC792]
    Icmp = 1,

    /// Internet Group Management [RFC1112]
    Igmp = 2,

    /// Gateway-to-Gateway [RFC823]
    Ggp = 3,

    /// IPv4 encapsulation [RFC2003]
    Ipv4 = 4,

    /// Stream [RFC1190][RFC1819]
    St = 5,

    /// Transmission Control [RFC793]
    Tcp = 6,

    /// CBT
    Cbt = 7,

    /// Exterior Gateway Protocol [RFC888]
    Egp = 8,

    /// any private interior gateway (used by Cisco for their IGRP)
    Igp = 9,

    /// BBN RCC Monitoring
    BbnRccMon = 10,

    /// Network Voice Protocol [RFC741]
    NvpII = 11,

    /// PUP
    Pup = 12,

    /// ARGUS
    Argus = 13,

    /// EMCON
    Emcon = 14,

    /// Cross Net Debugger
    Xnet = 15,

    /// Chaos
    Chaos = 16,

    /// User Datagram [RFC768]
    Udp = 17,

    /// Multiplexing
    Mux = 18,

    /// DCN Measurement Subsystems
    DcnMeas = 19,

    /// Host Monitoring [RFC869]
    Hmp = 20,

    /// Packet Radio Measurement
    Prm = 21,

    /// XEROX NS IDP
    XnsIdp = 22,

    /// Trunk-1
    Trunk1 = 23,

    /// Trunk-2
    Trunk2 = 24,

    /// Leaf-1
    Leaf1 = 25,

    /// Leaf-2
    Leaf2 = 26,

    /// Reliable Data Protocol [RFC908]
    Rdp = 27,

    /// Internet Reliable Transaction [RFC938]
    Irtp = 28,

    /// ISO Transport Protocol Class 4 [RFC905]
    IsoTp4 = 29,

    /// Bulk Data Transfer Protocol [RFC969]
    Netblt = 30,

    /// MFE Network Services Protocol
    MfeNsp = 31,

    /// MERIT Internodal Protocol
    MeritInp = 32,

    /// Datagram Congestion Control Protocol [RFC4340]
    Dccp = 33,

    /// Third Party Connect Protocol
    ThreePc = 34,

    /// Inter-Domain Policy Routing Protocol
    Idpr = 35,

    /// XTP
    Xtp = 36,

    /// Datagram Delivery Protocol
    Ddp = 37,

    /// IDPR Control Message Transport Proto
    IdprCmtp = 38,

    /// TP++ Transport Protocol
    TpPlusPlus = 39,

    /// IL Transport Protocol
    Il = 40,

    /// IPv6 encapsulation [RFC2473]
    Ipv6 = 41,

    /// Source Demand Routing Protocol
    Sdrp = 42,

    /// Routing Header for IPv6
    Ipv6Route = 43,

    /// Fragment Header for IPv6
    Ipv6Frag = 44,

    /// Inter-Domain Routing Protocol
    Idrp = 45,

    /// Reservation Protocol [RFC2205][RFC3209]
    Rsvp = 46,

    /// Generic Routing Encapsulation [RFC1701]
    Gre = 47,

    /// Dynamic Source Routing Protocol [RFC4728]
    Dsr = 48,

    /// BNA
    Bna = 49,

    /// Encap Security Payload [RFC4303]
    Esp = 50,

    /// Authentication Header [RFC4302]
    Ah = 51,

    /// Integrated Net Layer Security TUBA
    INlsp = 52,

    /// IP with Encryption
    Swipe = 53,

    /// NBMA Address Resolution Protocol [RFC1735]
    Narp = 54,

    /// IP Mobility
    Mobile = 55,

    /// Transport Layer Security Protocol using Kryptonet key management
    Tlsp = 56,

    /// SKIP
    Skip = 57,

    #[deprecated(note = "Please use `IpNextHeaderProtocols::Icmpv6` instead")]
    Ipv6Icmp = 58,

    /// ICMPv6 [RFC4443]
    Icmpv6 = 58,

    /// No Next Header for IPv6 [RFC2460]
    Ipv6NoNxt = 59,

    /// Destination Options for IPv6 [RFC2460]
    Ipv6Opts = 60,

    /// any host internal protocol
    HostInternal = 61,

    /// CFTP
    Cftp = 62,

    /// any local network
    LocalNetwork = 63,

    /// SATNET and Backroom EXPAK
    SatExpak = 64,

    /// Kryptolan
    Kryptolan = 65,

    /// MIT Remote Virtual Disk Protocol
    Rvd = 66,

    /// Internet Pluribus Packet Core
    Ippc = 67,

    /// any distributed file system
    DistributedFs = 68,

    /// SATNET Monitoring
    SatMon = 69,

    /// VISA Protocol
    Visa = 70,

    /// Internet Packet Core Utility
    Ipcv = 71,

    /// Computer Protocol Network Executive
    Cpnx = 72,

    /// Computer Protocol Heart Beat
    Cphb = 73,

    /// Wang Span Network
    Wsn = 74,

    /// Packet Video Protocol
    Pvp = 75,

    /// Backroom SATNET Monitoring
    BrSatMon = 76,

    /// SUN ND PROTOCOL-Temporary
    SunNd = 77,

    /// WIDEBAND Monitoring
    WbMon = 78,

    /// WIDEBAND EXPAK
    WbExpak = 79,

    /// ISO Internet Protocol
    IsoIp = 80,

    /// VMTP
    Vmtp = 81,

    /// SECURE-VMTP
    SecureVmtp = 82,

    /// VINES
    Vines = 83,

    /// Transaction Transport Protocol/IP Traffic Manager
    TtpOrIptm = 84,

    /// NSFNET-IGP
    NsfnetIgp = 85,

    /// Dissimilar Gateway Protocol
    Dgp = 86,

    /// TCF
    Tcf = 87,

    /// EIGRP
    Eigrp = 88,

    /// OSPFIGP [RFC1583][RFC2328][RFC5340]
    OspfigP = 89,

    /// Sprite RPC Protocol
    SpriteRpc = 90,

    /// Locus Address Resolution Protocol
    Larp = 91,

    /// Multicast Transport Protocol
    Mtp = 92,

    /// AX.25 Frames
    Ax25 = 93,

    /// IP-within-IP Encapsulation Protocol
    IpIp = 94,

    /// Mobile Internetworking Control Pro.
    Micp = 95,

    /// Semaphore Communications Sec. Pro.
    SccSp = 96,

    /// Ethernet-within-IP Encapsulation [RFC3378]
    Etherip = 97,

    /// Encapsulation Header [RFC1241]
    Encap = 98,

    /// any private encryption scheme
    PrivEncryption = 99,

    /// GMTP
    Gmtp = 100,

    /// Ipsilon Flow Management Protocol
    Ifmp = 101,

    /// PNNI over IP
    Pnni = 102,

    /// Protocol Independent Multicast [RFC4601]
    Pim = 103,

    /// ARIS
    Aris = 104,

    /// SCPS
    Scps = 105,

    /// QNX
    Qnx = 106,

    /// Active Networks
    AN = 107,

    /// IP Payload Compression Protocol [RFC2393]
    IpComp = 108,

    /// Sitara Networks Protocol
    Snp = 109,

    /// Compaq Peer Protocol
    CompaqPeer = 110,

    /// IPX in IP
    IpxInIp = 111,

    /// Virtual Router Redundancy Protocol [RFC5798]
    Vrrp = 112,

    /// PGM Reliable Transport Protocol
    Pgm = 113,

    /// any 0-hop protocol
    ZeroHop = 114,

    /// Layer Two Tunneling Protocol [RFC3931]
    L2tp = 115,

    /// D-II Data Exchange (DDX)
    Ddx = 116,

    /// Interactive Agent Transfer Protocol
    Iatp = 117,

    /// Schedule Transfer Protocol
    Stp = 118,

    /// SpectraLink Radio Protocol
    Srp = 119,

    /// UTI
    Uti = 120,

    /// Simple Message Protocol
    Smp = 121,

    /// Simple Multicast Protocol
    Sm = 122,

    /// Performance Transparency Protocol
    Ptp = 123,

    ///
    IsisOverIpv4 = 124,

    ///
    Fire = 125,

    /// Combat Radio Transport Protocol
    Crtp = 126,

    /// Combat Radio User Datagram
    Crudp = 127,

    ///
    Sscopmce = 128,

    ///
    Iplt = 129,

    /// Secure Packet Shield
    Sps = 130,

    /// Private IP Encapsulation within IP
    Pipe = 131,

    /// Stream Control Transmission Protocol
    Sctp = 132,

    /// Fibre Channel [RFC6172]
    Fc = 133,

    /// [RFC3175]
    RsvpE2eIgnore = 134,

    /// [RFC6275]
    MobilityHeader = 135,

    /// [RFC3828]
    UdpLite = 136,

    /// [RFC4023]
    MplsInIp = 137,

    /// MANET Protocols [RFC5498]
    Manet = 138,

    /// Host Identity Protocol [RFC5201]
    Hip = 139,

    /// Shim6 Protocol [RFC5533]
    Shim6 = 140,

    /// Wrapped Encapsulating Security Payload [RFC5840]
    Wesp = 141,

    /// Robust Header Compression [RFC5858]
    Rohc = 142,

    /// Use for experimentation and testing [RFC3692]
    Test1 = 253,

    /// Use for experimentation and testing [RFC3692]
    Test2 = 254,

    ///
    Reserved = 255,
}

#[test]
fn test() {
    for (r#const, value, display) in std::array::IntoIter::new([
        (IpNextHeaderProtocols::Skip, 57, "Skip"),
        (IpNextHeaderProtocols::Icmpv6, 58, "Icmpv6"),
        (IpNextHeaderProtocols::Ipv6NoNxt, 59, "Ipv6NoNxt"),
    ]) {
        assert_eq!(r#const, IpNextHeaderProtocol(value));
        assert_eq!(r#const.to_string(), display);
        assert_eq!(display.parse::<IpNextHeaderProtocol>().unwrap(), r#const);
    }

    #[allow(deprecated)]
    {
        assert_eq!(IpNextHeaderProtocols::Ipv6Icmp, IpNextHeaderProtocol(58));
        assert_eq!(IpNextHeaderProtocols::Ipv6Icmp.to_string(), "Icmpv6"); // Not "Ipv6Icmp"
        assert_eq!(
            "Ipv6Icmp".parse::<IpNextHeaderProtocol>().unwrap(),
            IpNextHeaderProtocols::Ipv6Icmp
        );
    }
}
