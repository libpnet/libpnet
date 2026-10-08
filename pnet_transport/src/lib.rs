// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for implementing transport layer protocols
//!
//! The transport module provides the ability to send and receive packets at
//! the transport layer using IPv4 or IPv6. It also enables layer 3 networking
//! for specific transport protocols, using IPv4 only.
//!
//! Note that this is limited by operating system support - for example, on OS
//! X and FreeBSD, it is impossible to implement protocols which are already
//! implemented in the kernel such as TCP and UDP.

#![deny(warnings)]
#![macro_use]

extern crate libc;
extern crate pnet_packet;
extern crate pnet_sys;

use self::TransportChannelType::{Layer3, Layer4};
use self::TransportProtocol::{Ipv4, Ipv6};
use pnet_packet::icmp::IcmpPacket;
use pnet_packet::icmpv6::Icmpv6Packet;
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;

use std::io;
use std::io::Error;
#[cfg(unix)]
use std::io::ErrorKind;
use std::mem;
use std::net::{self, IpAddr};
use std::sync::Arc;
#[cfg(unix)]
use std::time::Duration;

/// Represents a transport layer protocol.
#[derive(Clone, Copy)]
pub enum TransportProtocol {
    /// Represents a transport protocol built on top of IPv4
    Ipv4(IpNextHeaderProtocol),
    /// Represents a transport protocol built on top of IPv6
    Ipv6(IpNextHeaderProtocol),
}

/// Represents the valid codepoints for the Explicit Network Congestion in the IP header.
#[repr(u8)]
#[derive(Clone,Copy,Debug,PartialEq)]
pub enum Ecn {
    /// Not-ECT: The packet is not using ECN.
    NotEct = 0x0,
    /// ECT(1): The connection supports ECN.
    Ect1 = 0x1,
    /// ECT(0): The connection supports ECN.
    Ect0 = 0x2,
    /// CN: A host is notifying its peer that congestion has occurred.
    CE = 0x3
}

impl From<u8> for Ecn {
    fn from(value: u8) -> Ecn {
        let ecn_bits = value & 0x3;
        if ecn_bits == Ecn::Ect0 as u8 {
            return Ecn::Ect0
        } else if ecn_bits == Ecn::Ect1 as u8 {
            return Ecn::Ect1
        } else if ecn_bits == Ecn::CE as u8 {
            return Ecn::CE
        }
        Ecn::NotEct
    }
}

/// Type of transport channel to present.
#[derive(Clone, Copy)]
pub enum TransportChannelType {
    /// The application will send and receive transport layer packets.
    Layer4(TransportProtocol),
    /// The application will send and receive IPv4 packets, with the specified transport protocol.
    Layer3(IpNextHeaderProtocol),
}

/// Structure used for sending at the transport layer. Should be created with `transport_channel()`.
pub struct TransportSender {
    pub socket: Arc<pnet_sys::FileDesc>,
    channel_type: TransportChannelType,
}

/// Structure used for receiving at the transport layer. Should be created with `transport_channel()`.
pub struct TransportReceiver {
    pub socket: Arc<pnet_sys::FileDesc>,
    pub buffer: Vec<u8>,
    pub channel_type: TransportChannelType,
}

/// Structure used for holding all configurable options for describing possible options
/// for transport channels.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    time_to_live: u8,
}

/// Create a new `(TransportSender, TransportReceiver)` pair.
///
/// This allows for sending and receiving packets at the transport layer. The buffer size should be
/// large enough to handle the largest packet you wish to receive.
///
/// The channel type specifies what layer to send and receive packets at, and the transport
/// protocol you wish to implement. For example, `Layer4(Ipv4(IpNextHeaderProtocols::Udp))` would
/// allow sending and receiving UDP packets using IPv4; whereas `Layer3(IpNextHeaderProtocols::Udp)`
/// would include the IPv4 Header in received values, and require manual construction of an IP
/// header when sending.
pub fn transport_channel(
    buffer_size: usize,
    channel_type: TransportChannelType,
) -> io::Result<(TransportSender, TransportReceiver)> {
    // This hack makes sure that winsock is initialised
    let _ = {
        let ip = net::Ipv4Addr::new(255, 255, 255, 255);
        let sockaddr = net::SocketAddr::V4(net::SocketAddrV4::new(ip, 0));

        net::UdpSocket::bind(sockaddr)
    };

    let socket = unsafe {
        match channel_type {
            Layer4(Ipv4(IpNextHeaderProtocol(proto))) | Layer3(IpNextHeaderProtocol(proto)) => {
                pnet_sys::socket(pnet_sys::AF_INET, pnet_sys::SOCK_RAW, proto as libc::c_int)
            }
            Layer4(Ipv6(IpNextHeaderProtocol(proto))) => {
                pnet_sys::socket(pnet_sys::AF_INET6, pnet_sys::SOCK_RAW, proto as libc::c_int)
            }
        }
    };
    if socket == pnet_sys::INVALID_SOCKET {
        return Err(Error::last_os_error());
    }

    if matches!(channel_type, Layer3(_) | Layer4(Ipv4(_))) {
        let hincl: libc::c_int = match channel_type {
            Layer4(..) => 0,
            _ => 1,
        };
        let res = unsafe {
            pnet_sys::setsockopt(
                socket,
                pnet_sys::IPPROTO_IP,
                pnet_sys::IP_HDRINCL,
                (&hincl as *const libc::c_int) as pnet_sys::Buf,
                mem::size_of::<libc::c_int>() as pnet_sys::SockLen,
            )
        };
        if res == -1 {
            let err = Error::last_os_error();
            unsafe {
                pnet_sys::close(socket);
            }
            return Err(err);
        }
    }

    let sock = Arc::new(pnet_sys::FileDesc { fd: socket });
    let sender = TransportSender {
        socket: sock.clone(),
        channel_type,
    };
    let receiver = TransportReceiver {
        socket: sock,
        buffer: vec![0; buffer_size],
        channel_type,
    };

    Ok((sender, receiver))
}

/// Create a new `(TransportSender, TransportReceiver)` pair using the additional
/// options specified.
///
/// For a more exhaustive descriptive, see above.
pub fn transport_channel_with(
    buffer_size: usize,
    channel_type: TransportChannelType,
    configuration: Config,
) -> io::Result<(TransportSender, TransportReceiver)> {
    let (mut sender, receiver) = transport_channel(buffer_size, channel_type)?;

    sender.set_ttl(configuration.time_to_live)?;
    Ok((sender, receiver))
}

/// Sets a socket option whose value is a byte. Close the socket on error.
fn set_sockopt_u8(
    socket: Arc<pnet_sys::FileDesc>,
    level: libc::c_int,
    name: libc::c_int,
    value: u8,
) -> io::Result<()> {
    let value = value as i32;
    let res = unsafe {
        pnet_sys::setsockopt(
            socket.fd,
            level,
            name,
            (&value as *const libc::c_int) as pnet_sys::Buf,
            mem::size_of::<libc::c_int>() as pnet_sys::SockLen,
        )
    };

    match res {
        -1 => {
            let err = Error::last_os_error();
            unsafe {
                pnet_sys::close(socket.fd);
            }
            Err(err)
        }
        _ => Ok(()),
    }
}

impl TransportSender {
    fn send<T: Packet>(&mut self, packet: T, dst: IpAddr) -> io::Result<usize> {
        let mut caddr = unsafe { mem::zeroed() };
        let sockaddr = match dst {
            IpAddr::V4(ip_addr) => net::SocketAddr::V4(net::SocketAddrV4::new(ip_addr, 0)),
            IpAddr::V6(ip_addr) => net::SocketAddr::V6(net::SocketAddrV6::new(ip_addr, 0, 0, 0)),
        };
        let slen = pnet_sys::addr_to_sockaddr(sockaddr, &mut caddr);
        let caddr_ptr = (&caddr as *const pnet_sys::SockAddrStorage) as *const pnet_sys::SockAddr;

        pnet_sys::send_to(self.socket.fd, packet.packet(), caddr_ptr, slen)
    }

    /// Send a packet to the provided destination.
    #[inline]
    pub fn send_to<T: Packet>(&mut self, packet: T, destination: IpAddr) -> io::Result<usize> {
        self.send_to_impl(packet, destination)
    }

    /// Sets a time-to-live on the socket, which then applies for all packets sent.
    pub fn set_ttl(&mut self, time_to_live: u8) -> io::Result<()> {
        let (level, name) = match self.channel_type {
            Layer4(Ipv4(_)) | Layer3(_) => (pnet_sys::IPPROTO_IP, pnet_sys::IP_TTL),
            Layer4(Ipv6(_)) => (pnet_sys::IPPROTO_IPV6, pnet_sys::IPV6_UNICAST_HOPS),
        };
        set_sockopt_u8(self.socket.clone(), level, name, time_to_live)
    }

    /// Sets an ECN marking on the socket, which then applies for all packets sent.
    ///
    /// Marking a connection as ECN-capable or notifying the other end of a connection
    /// about network congestion can be done by setting the appropriate tos value. See
    /// RFC3168 for more information.
    #[cfg(unix)]
    pub fn set_ecn(&mut self, tos: Ecn) -> io::Result<()> {
        let (level, name) = match self.channel_type {
            Layer4(Ipv4(_)) | Layer3(_) => (pnet_sys::IPPROTO_IP, pnet_sys::IP_TOS),
            Layer4(Ipv6(_)) => (pnet_sys::IPPROTO_IPV6, pnet_sys::IPV6_TCLASS),
        };
        set_sockopt_u8(self.socket.clone(), level, name, tos as u8)
    }

    #[cfg(all(
        not(target_os = "freebsd"),
        not(any(target_os = "macos", target_os = "ios", target_os = "tvos"))
    ))]
    fn send_to_impl<T: Packet>(&mut self, packet: T, dst: IpAddr) -> io::Result<usize> {
        self.send(packet, dst)
    }

    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios", target_os = "tvos"))]
    fn send_to_impl<T: Packet>(&mut self, packet: T, dst: IpAddr) -> io::Result<usize> {
        use pnet_packet::ipv4::MutableIpv4Packet;
        use pnet_packet::MutablePacket;

        // FreeBSD and OS X expect total length and fragment offset fields of IPv4
        // packets to be in host byte order rather than network byte order. Fragment offset is the
        // ip_off field in the ip struct and contains both the offset and the three flag bits.
        // See `man 4 ip`/Raw IP Sockets)
        if let Layer3(_) = self.channel_type {
            let mut mut_slice: Vec<u8> = vec![0; packet.packet().len()];

            let mut new_packet = MutableIpv4Packet::new(&mut mut_slice[..]).unwrap();
            new_packet.clone_from(&packet);
            let length = new_packet.get_total_length().to_be();
            new_packet.set_total_length(length);
            {
                // Turn fragment offset into host order
                let d = new_packet.packet_mut();
                let host_order = u16::from_be((d[6] as u16) << 8 | d[7] as u16);
                d[6] = (host_order >> 8) as u8;
                d[7] = host_order as u8;
            }
            return self.send(new_packet, dst);
        }

        self.send(packet, dst)
    }
}

/// Create an iterator for some packet type.
///
/// Usage:
/// ```ignore
/// transport_channel_iterator!(Ipv4Packet, // Type to iterate over
///                             Ipv4TransportChannelIterator, // Name for iterator struct
///                             ipv4_packet_iter) // Name of function to create iterator
/// ```
#[macro_export]
macro_rules! transport_channel_iterator {
    ($ty:ident, $iter:ident, $func:ident) => {
        transport_channel_iterator!($ty, $iter, $func, stringify!($ty));
    };
    ($ty:ident, $iter:ident, $func:ident, $tyname:expr) => {
        #[doc = "An iterator over packets of type `"]
        #[doc = $tyname]
        #[doc = "`."]
        pub struct $iter<'a> {
            tr: &'a mut TransportReceiver,
        }

        #[doc = "Return a packet iterator with packets of type `"]
        #[doc = $tyname]
        #[doc = "` for some transport receiver."]
        pub fn $func(tr: &mut TransportReceiver) -> $iter<'_> {
            $iter { tr: tr }
        }

        impl<'a> $iter<'a> {
            #[doc = "Get the next (`"]
            #[doc = $tyname ]
            #[doc = "`, `IpAddr`) pair for the given channel."]
            pub fn next(&mut self) -> io::Result<($ty<'_>, IpAddr)> {
                let mut caddr: pnet_sys::SockAddrStorage = unsafe { mem::zeroed() };
                let res =
                    pnet_sys::recv_from(self.tr.socket.fd, &mut self.tr.buffer[..], &mut caddr);

                let offset = match self.tr.channel_type {
                    Layer4(Ipv4(_)) => {
                        let ip_header = Ipv4Packet::new(&self.tr.buffer[..]).unwrap();

                        ip_header.get_header_length() as usize * 4usize
                    }
                    Layer3(_) => {
                        fixup_packet(&mut self.tr.buffer[..]);

                        0
                    }
                    _ => 0,
                };
                return match res {
                    Ok(len) => {
                        let packet = $ty::new(&self.tr.buffer[offset..len]).unwrap();
                        let addr = pnet_sys::sockaddr_to_addr(
                            &caddr,
                            mem::size_of::<pnet_sys::SockAddrStorage>(),
                        );
                        let ip = match addr.unwrap() {
                            net::SocketAddr::V4(sa) => IpAddr::V4(*sa.ip()),
                            net::SocketAddr::V6(sa) => IpAddr::V6(*sa.ip()),
                        };
                        Ok((packet, ip))
                    }
                    Err(e) => Err(e),
                };

                #[cfg(any(
                    target_os = "freebsd",
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos"
                ))]
                fn fixup_packet(buffer: &mut [u8]) {
                    use pnet_packet::ipv4::MutableIpv4Packet;

                    let buflen = buffer.len();
                    let mut new_packet = MutableIpv4Packet::new(buffer).unwrap();

                    let length = u16::from_be(new_packet.get_total_length());
                    new_packet.set_total_length(length);

                    // OS X does this awesome thing where it removes the header length
                    // from the total length sometimes.
                    let length = new_packet.get_total_length() as usize
                        + (new_packet.get_header_length() as usize * 4usize);
                    if length == buflen {
                        new_packet.set_total_length(length as u16)
                    }

                    let offset = u16::from_be(new_packet.get_fragment_offset());
                    new_packet.set_fragment_offset(offset);
                }

                #[cfg(all(
                    not(target_os = "freebsd"),
                    not(any(target_os = "macos", target_os = "ios", target_os = "tvos"))
                ))]
                fn fixup_packet(_buffer: &mut [u8]) {}
            }

            /// Wait only for a timespan of `t` to receive some data, then return. If no data was
            /// received, then `Ok(None)` is returned.
            #[cfg(unix)]
            pub fn next_with_timeout(
                &mut self,
                t: Duration,
            ) -> io::Result<Option<($ty<'_>, IpAddr)>> {
                let socket_fd = self.tr.socket.fd;

                let old_timeout = match pnet_sys::get_socket_receive_timeout(socket_fd) {
                    Err(e) => {
                        eprintln!("Can not get socket timeout before receiving: {}", e);
                        return Err(e);
                    }
                    Ok(t) => t,
                };

                match pnet_sys::set_socket_receive_timeout(socket_fd, t) {
                    Err(e) => {
                        eprintln!("Can not set socket timeout for receiving: {}", e);
                        return Err(e);
                    }
                    Ok(_) => {}
                }

                let r = match self.next() {
                    Ok(r) => Ok(Some(r)),
                    Err(e) => match e.kind() {
                        ErrorKind::WouldBlock => Ok(None),
                        _ => Err(e),
                    },
                };

                match pnet_sys::set_socket_receive_timeout(socket_fd, old_timeout) {
                    Err(e) => {
                        eprintln!("Can not reset socket timeout after receiving: {}", e);
                    }
                    _ => {}
                };

                r
            }
        }
    };
}

transport_channel_iterator!(Ipv4Packet, Ipv4TransportChannelIterator, ipv4_packet_iter);

transport_channel_iterator!(UdpPacket, UdpTransportChannelIterator, udp_packet_iter);

transport_channel_iterator!(IcmpPacket, IcmpTransportChannelIterator, icmp_packet_iter);

transport_channel_iterator!(
    Icmpv6Packet,
    Icmpv6TransportChannelIterator,
    icmpv6_packet_iter
);

transport_channel_iterator!(TcpPacket, TcpTransportChannelIterator, tcp_packet_iter);
