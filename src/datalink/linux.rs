// Copyright (c) 2014-2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for sending and receiving data link layer packets using Linux's AF_PACKET

extern crate libc;

use std::cmp;
use std::io;
use std::iter::repeat;
use std::mem;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use bindings::linux;
use datalink::{self, NetworkInterface};
use datalink::Channel::Ethernet;
use datalink::{EthernetDataLinkChannelIterator,
               EthernetDataLinkReceiver,
               EthernetDataLinkSender,
               TimestampedEthernetDataLinkChannelIterator,
               TimestampedEthernetDataLinkReceiver,
               TimestampedEthernetPacket};
use datalink::ChannelType::{Layer2, Layer3};
use internal;
use sockets;
use packet::Packet;
use packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use util::MacAddr;

fn network_addr_to_sockaddr(ni: &NetworkInterface,
                            storage: *mut libc::sockaddr_storage,
                            proto: libc::c_int)
    -> usize {
    unsafe {
        let sll: *mut libc::sockaddr_ll = mem::transmute(storage);
        (*sll).sll_family = libc::AF_PACKET as libc::sa_family_t;
        if let Some(MacAddr(a, b, c, d, e, f)) = ni.mac {
            (*sll).sll_addr = [a, b, c, d, e, f, 0, 0];
        }
        (*sll).sll_protocol = (proto as u16).to_be();
        (*sll).sll_halen = 6;
        (*sll).sll_ifindex = ni.index as i32;
        mem::size_of::<libc::sockaddr_ll>()
    }
}

/// Configuration for the Linux datalink backend
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// The size of buffer to use when writing packets. Defaults to 4096
    pub write_buffer_size: usize,

    /// The size of buffer to use when reading packets. Defaults to 4096
    pub read_buffer_size: usize,

    /// The read timeout. Defaults to None.
    pub read_timeout: Option<Duration>,

    /// The write timeout. Defaults to None.
    pub write_timeout: Option<Duration>,

    /// Specifies whether timestamps should be received. Defaults to false.
    pub receive_hardware_timestamps: bool,

    /// Specifies whether to read packets at the datalink layer or network layer.
    /// NOTE FIXME Currently ignored
    /// Defaults to Layer2
    pub channel_type: datalink::ChannelType,
}

impl<'a> From<&'a datalink::Config> for Config {
    fn from(config: &datalink::Config) -> Config {
        Config {
            write_buffer_size: config.write_buffer_size,
            read_buffer_size: config.read_buffer_size,
            channel_type: config.channel_type,
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
            receive_hardware_timestamps: false,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: None,
            write_timeout: None,
            channel_type: Layer2,
            receive_hardware_timestamps: false,
        }
    }
}

/// Create a data link channel using the Linux's AF_PACKET socket type
#[inline]
pub fn channel(network_interface: &NetworkInterface, config: Config)
    -> io::Result<datalink::Channel> {
    let eth_p_all = 0x0003;
    let (typ, proto) = match config.channel_type {
        Layer2 => (libc::SOCK_RAW, eth_p_all),
        Layer3(EtherType(proto)) => (libc::SOCK_DGRAM, proto),
    };
    let socket = unsafe { libc::socket(libc::AF_PACKET, typ, proto.to_be() as i32) };
    if socket == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = network_addr_to_sockaddr(network_interface, &mut addr, proto as i32);

    let send_addr = (&addr as *const libc::sockaddr_storage) as *const libc::sockaddr;

    // Bind to interface
    if unsafe { libc::bind(socket, send_addr, len as libc::socklen_t) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            sockets::close(socket);
        }
        return Err(err);
    }

    let mut pmr: linux::packet_mreq = unsafe { mem::zeroed() };
    pmr.mr_ifindex = network_interface.index as i32;
    pmr.mr_type = linux::PACKET_MR_PROMISC as u16;

    // Enable promiscuous capture
    if unsafe {
        libc::setsockopt(socket,
                         linux::SOL_PACKET,
                         linux::PACKET_ADD_MEMBERSHIP,
                         (&pmr as *const linux::packet_mreq) as *const libc::c_void,
                         mem::size_of::<linux::packet_mreq>() as u32)
    } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            sockets::close(socket);
        }
        return Err(err);
    }

    // Enable nonblocking
    if unsafe {
        libc::fcntl(socket,
                    libc::F_SETFL,
                    libc::O_NONBLOCK)
    } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            sockets::close(socket);
        }
        return Err(err);
    }

    let fd = Arc::new(internal::FileDesc { fd: socket });
    let mut sender = Box::new(DataLinkSenderImpl {
        socket: fd.clone(),
        fd_set: unsafe { mem::zeroed() },
        write_buffer: repeat(0u8).take(config.write_buffer_size).collect(),
        _channel_type: config.channel_type,
        send_addr: unsafe { *(send_addr as *const libc::sockaddr_ll) },
        send_addr_len: len,
        timeout: config.write_timeout.map(|to| internal::duration_to_timespec(to))
    });
    unsafe {
        libc::FD_ZERO(&mut sender.fd_set as *mut libc::fd_set);
        libc::FD_SET(fd.fd, &mut sender.fd_set as *mut libc::fd_set);
    }
    let mut receiver = Box::new(DataLinkReceiverImpl {
        socket: fd.clone(),
        fd_set: unsafe { mem::zeroed() },
        read_buffer: repeat(0u8).take(config.read_buffer_size).collect(),
        _channel_type: config.channel_type,
        timeout: config.read_timeout.map(|to| internal::duration_to_timespec(to))
    });
    unsafe {
        libc::FD_ZERO(&mut receiver.fd_set as *mut libc::fd_set);
        libc::FD_SET(fd.fd, &mut receiver.fd_set as *mut libc::fd_set);
    }

    if config.receive_hardware_timestamps {
        Ok(TimestampedEthernet(sender, receiver))
    } else {
        Ok(Ethernet(sender, receiver))
    }
}

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<NetworkInterface> {
    #[path = "unix_interfaces.rs"]
    mod interfaces;
    interfaces::interfaces()
}

struct DataLinkSenderImpl {
    socket: Arc<internal::FileDesc>,
    fd_set: libc::fd_set,
    write_buffer: Vec<u8>,
    _channel_type: datalink::ChannelType,
    send_addr: libc::sockaddr_ll,
    send_addr_len: usize,
    timeout: Option<libc::timespec>,
}

impl EthernetDataLinkSender for DataLinkSenderImpl {
    // FIXME Layer 3
    #[inline]
    fn build_and_send(&mut self,
                      num_packets: usize,
                      packet_size: usize,
                      func: &mut FnMut(MutableEthernetPacket))
        -> Option<io::Result<()>> {
        let len = num_packets * packet_size;
        if len < self.write_buffer.len() {
            let min = cmp::min(self.write_buffer[..].len(), len);
            let mut mut_slice = &mut self.write_buffer;
            for chunk in mut_slice[..min].chunks_mut(packet_size) {
                {
                    let eh = MutableEthernetPacket::new(chunk).unwrap();
                    func(eh);
                }
                let send_addr =
                    (&self.send_addr as *const libc::sockaddr_ll) as *const libc::sockaddr;

                let ret = unsafe {
                    libc::pselect(self.socket.fd + 1,
                                  ptr::null_mut(),
                                  &mut self.fd_set as *mut libc::fd_set,
                                  ptr::null_mut(),
                                  self.timeout.map(|to| &to as *const libc::timespec)
                                  .unwrap_or(ptr::null()),
                                  ptr::null())
                };
                if ret == -1 {
                    return Some(Err(io::Error::last_os_error()));
                } else if ret == 0 {
                    return Some(Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")));
                } else {
                    if let Err(e) =  internal::send_to(self.socket.fd,
                                                    chunk,
                                                    send_addr,
                                                    self.send_addr_len as libc::socklen_t) {
                        return Some(Err(e));
                    }
                }
            }

            Some(Ok(()))
        } else {
            None
        }
    }

    #[inline]
    fn send_to(&mut self,
               packet: &EthernetPacket,
               _dst: Option<NetworkInterface>)
        -> Option<io::Result<()>> {
        let ret = unsafe {
            libc::pselect(self.socket.fd + 1,
                          ptr::null_mut(),
                          &mut self.fd_set as *mut libc::fd_set,
                          ptr::null_mut(),
                          self.timeout.map(|to| &to as *const libc::timespec)
                          .unwrap_or(ptr::null()),
                          ptr::null())
        };
        if ret == -1 {
            Some(Err(io::Error::last_os_error()))
        } else if ret == 0 {
            Some(Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")))
        } else {
            match internal::send_to(self.socket.fd,
                                    packet.packet(),
                                    (&self.send_addr as *const libc::sockaddr_ll) as *const _,
                                    self.send_addr_len as libc::socklen_t) {
                Err(e) => Some(Err(e)),
                Ok(_) => Some(Ok(())),
            }
        }
    }
}

struct DataLinkReceiverImpl {
    socket: Arc<internal::FileDesc>,
    fd_set: libc::fd_set,
    read_buffer: Vec<u8>,
    _channel_type: datalink::ChannelType,
    timeout: Option<libc::timespec>,
}

impl EthernetDataLinkReceiver for DataLinkReceiverImpl {
    // FIXME Layer 3
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a> {
        Box::new(DataLinkChannelIteratorImpl { pc: self })
    }
}

impl TimestampedEthernetDataLinkReceiver for DataLinkReceiverImpl {
    // FIXME Layer 3
    fn iter<'a>(&'a mut self) -> Box<TimestampedEthernetDataLinkChannelIterator + 'a> {
        Box::new(DataLinkChannelIteratorImpl { pc: self })
    }
}

struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
}

impl<'a> EthernetDataLinkChannelIterator<'a> for DataLinkChannelIteratorImpl<'a> {
    fn next(&mut self) -> io::Result<EthernetPacket> {
        let mut caddr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let ret = unsafe {
            libc::pselect(self.pc.socket.fd + 1,
                          &mut self.pc.fd_set as *mut libc::fd_set,
                          ptr::null_mut(),
                          ptr::null_mut(),
                          self.pc.timeout.map(|to| &to as *const libc::timespec)
                          .unwrap_or(ptr::null()),
                          ptr::null())
        };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else if ret == 0 {
            Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"))
        } else {
            let res = internal::recv_from(self.pc.socket.fd, &mut self.pc.read_buffer, &mut caddr);
            match res {
                Ok(len) => Ok(EthernetPacket::new(&self.pc.read_buffer[0..len]).unwrap()),
                Err(e) => Err(e),
            }
        }
    }
}

impl<'a> TimestampedEthernetDataLinkChannelIterator<'a> for DataLinkChannelIteratorImpl<'a> {
    fn next(&mut self) -> io::Result<TimestampedEthernetPacket> {
        let mut caddr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        internal::recv_from(self.pc.socket.fd, &mut self.pc.read_buffer, &mut caddr)
            .and_then(move |len| {
                let mut tv_ioctl: libc::timeval = unsafe { mem::zeroed() };
                if unsafe {
                    linux::ioctl(self.pc.socket.fd,
                                 linux::SIOCGSTAMP,
                                 (&mut tv_ioctl as *mut libc::timeval))
                } == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(TimestampedEthernetPacket(
                        internal::timeval_to_duration(tv_ioctl),
                        EthernetPacket::new(&self.pc.read_buffer[0..len]).unwrap()))
                }
            })
    }
}
