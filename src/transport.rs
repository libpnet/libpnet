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

#![macro_use]

extern crate libc;


use internal;

use packet::Packet;
use packet::ip::IpNextHeaderProtocol;
use packet::ipv4::Ipv4Packet;
use packet::udp::UdpPacket;
use packet::icmp::IcmpPacket;
use packet::tcp::TcpPacket;
use self::TransportChannelType::{Layer3, Layer4};
use self::TransportProtocol::{Ipv4, Ipv6};
use sockets;

use std::io;
use std::io::Error;
use std::iter::repeat;
use std::mem;
use std::net::{self, IpAddr};
use std::sync::Arc;

/// Represents a transport layer protocol
#[derive(Clone, Copy)]
pub enum TransportProtocol {
    /// Represents a transport protocol built on top of IPv4
    Ipv4(IpNextHeaderProtocol),
    /// Represents a transport protocol built on top of IPv6
    Ipv6(IpNextHeaderProtocol),
}

/// Type of transport channel to present
#[derive(Clone, Copy)]
pub enum TransportChannelType {
    /// The application will send and receive transport layer packets
    Layer4(TransportProtocol),
    /// The application will send and receive IPv4 packets, with the specified transport protocol
    Layer3(IpNextHeaderProtocol),
}

/// Structure used for sending at the transport layer. Should be created with transport_channel()
pub struct TransportSender {
    socket: Arc<internal::FileDesc>,
    _channel_type: TransportChannelType,
}

/// Structure used for receiving at the transport layer. Should be created with transport_channel()
pub struct TransportReceiver {
    socket: Arc<internal::FileDesc>,
    buffer: Vec<u8>,
    channel_type: TransportChannelType,
}

/// Create a new (TransportSender, TransportReceiver) pair
///
/// This allows for sending and receiving packets at the transport layer. The buffer size should be
/// large enough to handle the largest packet you wish to receive.
///
/// The channel type specifies what layer to send and receive packets at, and the transport
/// protocol you wish to implement. For example, `Layer4(Ipv4(IpNextHeaderProtocols::Udp))` would
/// allow sending and receiving UDP packets using IPv4; whereas Layer3(IpNextHeaderProtocols::Udp)
/// would include the IPv4 Header in received values, and require manual construction of an IP
/// header when sending.
pub fn transport_channel(buffer_size: usize,
                         channel_type: TransportChannelType)
    -> io::Result<(TransportSender, TransportReceiver)> {
    use std::net;

    // This hack makes sure that winsock is initialised
    let _ = {
        let ip = net::Ipv4Addr::new(255, 255, 255, 255);
        let sockaddr = net::SocketAddr::V4(net::SocketAddrV4::new(ip, 0));

        net::UdpSocket::bind(sockaddr)
    };

    let socket = unsafe {
        match channel_type {
            Layer4(Ipv4(IpNextHeaderProtocol(proto))) |
            Layer3(IpNextHeaderProtocol(proto)) => {
                sockets::socket(sockets::AF_INET, sockets::SOCK_RAW, proto as libc::c_int)
            }
            Layer4(Ipv6(IpNextHeaderProtocol(proto))) => {
                sockets::socket(sockets::AF_INET6, sockets::SOCK_RAW, proto as libc::c_int)
            }
        }
    };
    if socket == sockets::INVALID_SOCKET {
        return Err(Error::last_os_error());
    }

    if match channel_type {
        Layer3(_) | Layer4(Ipv4(_)) => true,
        _ => false,
    } {
        let hincl: libc::c_int = match channel_type {
            Layer4(..) => 0,
            _ => 1,
        };
        let res = unsafe {
            sockets::setsockopt(socket,
                                sockets::IPPROTO_IP,
                                sockets::IP_HDRINCL,
                                (&hincl as *const libc::c_int) as sockets::Buf,
                                mem::size_of::<libc::c_int>() as sockets::SockLen)
        };
        if res == -1 {
            let err = Error::last_os_error();
            unsafe {
                sockets::close(socket);
            }
            return Err(err);
        }
    }

    let sock = Arc::new(internal::FileDesc { fd: socket });
    let sender = TransportSender {
        socket: sock.clone(),
        _channel_type: channel_type,
    };
    let receiver = TransportReceiver {
        socket: sock,
        buffer: repeat(0u8).take(buffer_size).collect(),
        channel_type: channel_type,
    };

    Ok((sender, receiver))
}

impl TransportSender {
    fn send<T: Packet>(&mut self, packet: T, dst: IpAddr) -> io::Result<usize> {
        let mut caddr = unsafe { mem::zeroed() };
        let sockaddr = match dst {
            IpAddr::V4(ip_addr) => net::SocketAddr::V4(net::SocketAddrV4::new(ip_addr, 0)),
            IpAddr::V6(ip_addr) => net::SocketAddr::V6(net::SocketAddrV6::new(ip_addr, 0, 0, 0)),
        };
        let slen = internal::addr_to_sockaddr(sockaddr, &mut caddr);
        let caddr_ptr = (&caddr as *const sockets::SockAddrStorage) as *const sockets::SockAddr;

        internal::send_to(self.socket.fd, packet.packet(), caddr_ptr, slen)
    }

    /// Send a packet to the provided destination
    #[inline]
    pub fn send_to<T: Packet>(&mut self, packet: T, destination: IpAddr) -> io::Result<usize> {
        self.send_to_impl(packet, destination)
    }

    #[cfg(all(not(target_os = "freebsd"), not(target_os = "macos")))]
    fn send_to_impl<T: Packet>(&mut self, packet: T, dst: IpAddr) -> io::Result<usize> {
        self.send(packet, dst)
    }

    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    fn send_to_impl<T: Packet>(&mut self, packet: T, dst: IpAddr) -> io::Result<usize> {
        use packet::MutablePacket;
        use packet::ipv4::MutableIpv4Packet;

        // FreeBSD and OS X expect total length and fragment offset fields of IPv4
        // packets to be in host byte order rather than network byte order. Fragment offset is the
        // ip_off field in the ip struct and contains both the offset and the three flag bits.
        // See `man 4 ip`/Raw IP Sockets)
        if let Layer3(_) = self._channel_type {
            let mut mut_slice: Vec<u8> = repeat(0u8).take(packet.packet().len()).collect();

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

/// Create methods to set a particular flag if compiled for particular platforms
#[macro_export]
macro_rules! create_set_flag_method {
    ($method:ident, $flag:expr, $platforms:meta) => (
        /// Set command line flag if available for the current platform
        #[cfg($platforms)]
        pub fn $method(&mut self, enabled: bool) -> Result<(), ()> {
            if enabled {
                self.flags = self.flags | $flag;
            } else {
                self.flags = self.flags & !$flag;
            }
            Ok(())
        }
        /// Set command line flag if available for the current platform
        #[cfg(not($platforms))]
        pub fn $method(&mut self, _enabled: bool) -> Result<(), ()> {
            Err(())
        }
    )
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
    ($ty:ident, $iter:ident, $func:ident) => (
        /// An iterator over packets of type $ty
        pub struct $iter<'a> {
            tr: &'a mut TransportReceiver,
            flags: i32
        }
        /// Return a packet iterator with packets of type $ty for some transport receiver
        pub fn $func(tr: &mut TransportReceiver) -> $iter {
            $iter {
                tr: tr,
                flags: 0
            }
        }
        impl<'a> $iter<'a> {
            create_set_flag_method!(
                set_process_out_of_band_data,
                libc::MSG_OOB,
                any(target_os = "windows", target_os = "macos", target_os = "freebsd", target_os = "linux")
            );
            create_set_flag_method!(
                set_peek_incoming_data,
                libc::MSG_PEEK,
                any(target_os = "windows", target_os = "macos", target_os = "freebsd", target_os = "linux")
            );
            create_set_flag_method!(
                set_wait_for_full_request,
                libc::MSG_WAITALL,
                any(target_os = "macos", target_os = "freebsd", target_os = "linux")
            );
            create_set_flag_method!(
                set_nonblocking,
                libc::MSG_DONTWAIT,
                any(target_os = "freebsd", target_os = "linux")
            );
            create_set_flag_method!(
                set_close_on_exec,
                libc::MSG_CMSG_CLOEXEC,
                // recvmsg() only for Linux (since Linux 2.6.23)
                any(target_os = "freebsd")
            );
            create_set_flag_method!(
                set_error_queue,
                libc::MSG_ERRQUEUE,
                any(target_os = "linux")
            );
            create_set_flag_method!(
                set_truncate,
                libc::MSG_TRUNC,
                any(target_os = "linux")
            );
            /// Get the next ($ty, IpAddr) pair for the given channel
            pub fn next(&mut self) -> io::Result<($ty, IpAddr)> {
                let mut caddr: sockets::SockAddrStorage = unsafe { mem::zeroed() };
                let res = internal::recv_from(self.tr.socket.fd,
                                              &mut self.tr.buffer[..],
                                              &mut caddr,
                                              self.flags);

                let offset = match self.tr.channel_type {
                    Layer4(Ipv4(_)) => {
                        let ip_header = Ipv4Packet::new(&self.tr.buffer[..]).unwrap();

                        ip_header.get_header_length() as usize * 4usize
                    },
                    Layer3(_) => {
                        fixup_packet(&mut self.tr.buffer[..]);

                        0
                    },
                    _ => 0
                };
                return match res {
                    Ok(len) => {
                        let packet = $ty::new(&self.tr.buffer[offset..len]).unwrap();
                        let addr = internal::sockaddr_to_addr(
                                        &caddr,
                                        mem::size_of::<sockets::SockAddrStorage>()
                                   );
                        let ip = match addr.unwrap() {
                            net::SocketAddr::V4(sa) => IpAddr::V4(*sa.ip()),
                            net::SocketAddr::V6(sa) => IpAddr::V6(*sa.ip()),
                        };
                        Ok((packet, ip))
                    },
                    Err(e) => Err(e),
                };

                #[cfg(any(target_os = "freebsd", target_os = "macos"))]
                fn fixup_packet(buffer: &mut [u8]) {
                    use packet::ipv4::MutableIpv4Packet;

                    let buflen = buffer.len();
                    let mut new_packet = MutableIpv4Packet::new(buffer).unwrap();

                    let length = u16::from_be(new_packet.get_total_length());
                    new_packet.set_total_length(length);

                    // OS X does this awesome thing where it removes the header length
                    // from the total length sometimes.
                    let length = new_packet.get_total_length() as usize +
                                 (new_packet.get_header_length() as usize * 4usize);
                    if length == buflen {
                        new_packet.set_total_length(length as u16)
                    }

                    let offset = u16::from_be(new_packet.get_fragment_offset());
                    new_packet.set_fragment_offset(offset);
                }

                #[cfg(all(not(target_os = "freebsd"), not(target_os = "macos")))]
                fn fixup_packet(_buffer: &mut [u8]) {}
            }
        }
    )
}

transport_channel_iterator!(Ipv4Packet, Ipv4TransportChannelIterator, ipv4_packet_iter);

transport_channel_iterator!(UdpPacket, UdpTransportChannelIterator, udp_packet_iter);

transport_channel_iterator!(IcmpPacket, IcmpTransportChannelIterator, icmp_packet_iter);

transport_channel_iterator!(TcpPacket, TcpTransportChannelIterator, tcp_packet_iter);
