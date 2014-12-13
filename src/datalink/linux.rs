// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp;
use std::io::{IoResult, IoError};
use std::mem;
use std::num::Int;
use std::sync::Arc;

use bindings::libc;
use bindings::linux;
use datalink::DataLinkChannelType;
use datalink::DataLinkChannelType::{Layer2, Layer3};
use internal;
use packet::Packet;
use packet::ethernet::{EtherType, EthernetHeader, MutableEthernetHeader};
use util::{NetworkInterface, MacAddr};

fn network_addr_to_sockaddr(ni: &NetworkInterface,
                            storage: *mut libc::sockaddr_storage,
                            proto: libc::c_int) -> uint {
    unsafe {
        let sll: *mut libc::sockaddr_ll = mem::transmute(storage);
        (*sll).sll_family = libc::AF_PACKET as libc::sa_family_t;
        match ni.mac {
            Some(MacAddr(a, b, c, d, e, f)) => (*sll).sll_addr = [a, b, c, d, e, f, 0, 0],
            _ => ()
        }
        (*sll).sll_protocol = (proto as u16).to_be();
        (*sll).sll_halen = 6;
        (*sll).sll_ifindex = ni.index as i32;
        mem::size_of::<libc::sockaddr_ll>()
    }
}

pub struct DataLinkSenderImpl {
    socket: Arc<internal::FileDesc>,
    write_buffer: Vec<u8>,
    _channel_type: DataLinkChannelType,
    send_addr: libc::sockaddr_ll,
    send_addr_len: uint
}

impl DataLinkSenderImpl {
    // FIXME Layer 3
    pub fn build_and_send(&mut self, num_packets: uint, packet_size: uint,
                          func: |MutableEthernetHeader| -> ()) -> Option<IoResult<()>> {
        let len = num_packets * packet_size;
        if len < self.write_buffer.as_slice().len() {
            let min = cmp::min(self.write_buffer.as_slice().len(), len);
            let ref mut mut_slice = self.write_buffer;
            for chunk in mut_slice.as_mut_slice().slice_to_mut(min)
                                  .chunks_mut(packet_size) {
                {
                    let eh = MutableEthernetHeader::new(chunk);
                    func(eh);
                }
                let send_addr = (&self.send_addr as *const libc::sockaddr_ll)
                                                 as *const libc::sockaddr;
                match internal::send_to(self.socket.fd, chunk, send_addr,
                                             self.send_addr_len as libc::socklen_t) {
                    Err(e) => return Some(Err(e)),
                    Ok(_) => ()
                }
            }
            Some(Ok(()))
        } else {
            None
        }
    }

    pub fn send_to(&mut self, packet: EthernetHeader, _dst: Option<NetworkInterface>)
        -> Option<IoResult<()>> {
        match internal::send_to(self.socket.fd,
                                packet.packet(),
                                (&self.send_addr as *const libc::sockaddr_ll) as *const _,
                                self.send_addr_len as libc::socklen_t) {
            Err(e) => Some(Err(e)),
            Ok(_) => Some(Ok(()))
        }
    }
}

pub struct DataLinkReceiverImpl {
    socket: Arc<internal::FileDesc>,
    read_buffer: Vec<u8>,
    _channel_type: DataLinkChannelType,
}

impl DataLinkReceiverImpl {
    // FIXME Layer 3
    pub fn iter<'a>(&'a mut self) -> DataLinkChannelIteratorImpl<'a> {
        DataLinkChannelIteratorImpl {
            pc: self,
        }
    }
}

pub fn datalink_channel (network_interface: &NetworkInterface,
                         write_buffer_size: uint,
                         read_buffer_size: uint,
                         channel_type: DataLinkChannelType)
    -> IoResult<(DataLinkSenderImpl, DataLinkReceiverImpl)> {
    let eth_p_all = 0x0003;
    let (typ, proto) = match channel_type {
        Layer2 => (libc::SOCK_RAW, eth_p_all),
        Layer3(EtherType(proto)) => (libc::SOCK_DGRAM, proto),
    };
    let socket = unsafe { libc::socket(libc::AF_PACKET, typ, proto.to_be() as i32) };
    if socket != -1 {
        let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let len = network_addr_to_sockaddr(network_interface,
                                           &mut addr,
                                           proto as i32);

        let send_addr = (&addr as *const libc::sockaddr_storage) as *const libc::sockaddr;

        // Bind to interface
        if unsafe { libc::bind(socket, send_addr, len as libc::socklen_t) } == -1 {
            let err = IoError::last_error();
            unsafe { internal::close(socket); }
            return Err(err);
        }

        let mut pmr: linux::packet_mreq = unsafe { mem::zeroed() };
        pmr.mr_ifindex = network_interface.index as i32;
        pmr.mr_type = linux::PACKET_MR_PROMISC as u16;

        // Enable promiscuous capture
        if unsafe { libc::setsockopt(socket,
                                     linux::SOL_PACKET,
                                     linux::PACKET_ADD_MEMBERSHIP,
                                     (&pmr as *const linux::packet_mreq)
                                           as *const libc::c_void,
                                     mem::size_of::<linux::packet_mreq>() as u32) } == -1 {
            let err = IoError::last_error();
            unsafe { internal::close(socket); }
            return Err(err);
        }

        let fd = Arc::new(internal::FileDesc { fd: socket });
        let sender = DataLinkSenderImpl {
            socket: fd.clone(),
            write_buffer: Vec::from_elem(write_buffer_size, 0u8),
            _channel_type: channel_type,
            send_addr: unsafe { *(send_addr as *const libc::sockaddr_ll) },
            send_addr_len: len,
        };
        let receiver = DataLinkReceiverImpl {
            socket: fd,
            read_buffer: Vec::from_elem(read_buffer_size, 0u8),
            _channel_type: channel_type
        };
        Ok((sender, receiver))
    } else {
        Err(IoError::last_error())
    }
}

pub struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
}

impl<'a> DataLinkChannelIteratorImpl<'a> {
    pub fn next<'c>(&'c mut self) -> IoResult<EthernetHeader<'c>> {
        let mut caddr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let res = internal::recv_from(self.pc.socket.fd, self.pc.read_buffer.as_mut_slice(), &mut caddr);
        match res {
            Ok(len) => Ok(EthernetHeader::new(self.pc.read_buffer.as_slice().slice(0, len))),
            Err(e) => Err(e),
        }
    }
}

