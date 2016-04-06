// Copyright (c) 2014-2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;

use std::cmp;
use std::io;
use std::iter::repeat;
use std::mem;
use std::sync::Arc;

use bindings::linux;
use datalink::{EthernetDataLinkChannelIterator, DataLinkChannelType, EthernetDataLinkReceiver,
               EthernetDataLinkSender};
use datalink::DataLinkChannelType::{Layer2, Layer3};
use internal;
use packet::Packet;
use packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use util::{MacAddr, NetworkInterface};

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

#[inline]
pub fn datalink_channel(network_interface: &NetworkInterface,
                        write_buffer_size: usize,
                        read_buffer_size: usize,
                        channel_type: DataLinkChannelType)
    -> io::Result<(Box<EthernetDataLinkSender>, Box<EthernetDataLinkReceiver>)> {
    let eth_p_all = 0x0003;
    let (typ, proto) = match channel_type {
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
            internal::close(socket);
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
            internal::close(socket);
        }
        return Err(err);
    }

    let fd = Arc::new(internal::FileDesc { fd: socket });
    let sender = Box::new(DataLinkSenderImpl {
        socket: fd.clone(),
        write_buffer: repeat(0u8).take(write_buffer_size).collect(),
        _channel_type: channel_type,
        send_addr: unsafe { *(send_addr as *const libc::sockaddr_ll) },
        send_addr_len: len,
    });
    let receiver = Box::new(DataLinkReceiverImpl {
        socket: fd,
        read_buffer: repeat(0u8).take(read_buffer_size).collect(),
        _channel_type: channel_type,
    });

    Ok((sender, receiver))
}

pub struct DataLinkSenderImpl {
    socket: Arc<internal::FileDesc>,
    write_buffer: Vec<u8>,
    _channel_type: DataLinkChannelType,
    send_addr: libc::sockaddr_ll,
    send_addr_len: usize,
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

                if let Err(e) =  internal::send_to(self.socket.fd,
                                                   chunk,
                                                   send_addr,
                                                   self.send_addr_len as libc::socklen_t) {
                    return Some(Err(e));
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
        match internal::send_to(self.socket.fd,
                                packet.packet(),
                                (&self.send_addr as *const libc::sockaddr_ll) as *const _,
                                self.send_addr_len as libc::socklen_t) {
            Err(e) => Some(Err(e)),
            Ok(_) => Some(Ok(())),
        }
    }
}

pub struct DataLinkReceiverImpl {
    socket: Arc<internal::FileDesc>,
    read_buffer: Vec<u8>,
    _channel_type: DataLinkChannelType,
}

impl EthernetDataLinkReceiver for DataLinkReceiverImpl {
    // FIXME Layer 3
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a> {
        Box::new(DataLinkChannelIteratorImpl { pc: self })
    }
}

pub struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
}

impl<'a> EthernetDataLinkChannelIterator<'a> for DataLinkChannelIteratorImpl<'a> {
    fn next(&mut self) -> io::Result<EthernetPacket> {
        let mut caddr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let res = internal::recv_from(self.pc.socket.fd, &mut self.pc.read_buffer, &mut caddr);
        match res {
            Ok(len) => Ok(EthernetPacket::new(&self.pc.read_buffer[0..len]).unwrap()),
            Err(e) => Err(e),
        }
    }
}
