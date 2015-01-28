// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(bad_style)]
#![unstable]

extern crate "rust-netmap" as netmap;
extern crate libc;

use libc::{c_int, c_uint, c_ulong, c_short};
use self::netmap::netmap_user::{nm_open, nm_close, nm_nextpkt, nm_desc, nm_pkthdr,
                                nm_ring_next, NETMAP_TXRING, NETMAP_FD, NETMAP_BUF};
use self::netmap::netmap::{nm_ring_empty, netmap_slot};

use std::ffi::CString;
use std::path::Path;
use std::old_io::fs::File;
use std::old_io::{IoResult, IoError};
use std::mem;
use std::num;
use std::ptr;
use std::raw;
use std::sync::Arc;

use datalink::DataLinkChannelType;
use packet::Packet;
use packet::ethernet::{EthernetHeader, MutableEthernetHeader};
use util::{NetworkInterface};

#[cfg(target_os = "linux")]
#[repr(C)]
struct pollfd {
    fd: c_int,
    events: c_short,
    revents: c_short
}

#[cfg(target_os = "linux")]
const POLLIN: c_short = 0x0001;
#[cfg(target_os = "linux")]
const POLLOUT: c_short = 0x0004;

type nfds_t = c_ulong;

extern {
    fn poll(fds: *mut pollfd, nfds: nfds_t, timeout: c_int) -> c_int;
}

struct NmDesc {
    desc: *mut nm_desc,
    buf_size: c_uint,
}

impl NmDesc {
    fn new(iface: &NetworkInterface) -> IoResult<NmDesc> {
        let ifname = CString::from_slice(("netmap:".to_string() + iface.name.as_slice()).as_bytes());
        let desc = unsafe {
            nm_open(ifname.as_ptr(), ptr::null(), 0, ptr::null())
        };

        if desc.is_null() {
            Err(IoError::last_error())
        } else {
            let mut f = try!(File::open(&Path::new("/sys/module/netmap/parameters/buf_size")));
            let num_str = try!(f.read_to_string());
            let buf_size = num_str.trim_right().parse().unwrap();

            Ok(NmDesc {
                desc: desc,
                buf_size: buf_size
            })
        }
    }
}

impl Drop for NmDesc {
    fn drop(&mut self) {
        unsafe {
            nm_close(self.desc);
        }
    }
}


pub struct DataLinkSenderImpl {
    desc: Arc<NmDesc>
}

impl DataLinkSenderImpl {
    pub fn build_and_send<F>(&mut self, num_packets: usize, packet_size: usize,
                          func: &mut F) -> Option<IoResult<()>>
        where F : FnMut(MutableEthernetHeader)
    {
        assert!(num::cast::<usize, u16>(packet_size).unwrap() as c_uint <= self.desc.buf_size);
        let desc = self.desc.desc;
        let mut fds = pollfd {
            fd: unsafe { NETMAP_FD(desc) },
            events: POLLOUT,
            revents: 0,
        };
        let mut packet_idx = 0us;
        while packet_idx < num_packets {
            unsafe {
                if poll(&mut fds, 1, -1) < 0 {
                    return Some(Err(IoError::last_error()));
                }
                let ring = NETMAP_TXRING((*desc).nifp, 0);
                while !nm_ring_empty(ring) && packet_idx < num_packets {
                    let i = (*ring).cur;
                    let slot_ptr: *mut netmap_slot = mem::transmute(&mut (*ring).slot);
                    let buf = NETMAP_BUF(ring, (*slot_ptr.offset(i as isize)).buf_idx as isize);
                    let slice = raw::Slice { data: buf, len: packet_size };
                    let meh = MutableEthernetHeader::new(mem::transmute(slice));
                    (*slot_ptr.offset(i as isize)).len = packet_size as u16;
                    func(meh);
                    let next = nm_ring_next(ring, i);
                    (*ring).head = next;
                    (*ring).cur =  next;
                    packet_idx += 1;
                }
            }
        }

        Some(Ok(()))
    }

    pub fn send_to(&mut self, packet: EthernetHeader, _dst: Option<NetworkInterface>)
        -> Option<IoResult<()>> {
        use packet::MutablePacket;
        self.build_and_send(1, packet.packet().len(), &mut |&mut:mut eh: MutableEthernetHeader| {
            eh.clone_from(packet);
        })
    }
}

pub struct DataLinkReceiverImpl {
    desc: Arc<NmDesc>,
}

impl DataLinkReceiverImpl {
    // FIXME Layer 3
    pub fn iter<'a>(&'a mut self) -> DataLinkChannelIteratorImpl<'a> {
        DataLinkChannelIteratorImpl {
            pc: self,
        }
    }
}

pub fn datalink_channel(network_interface: &NetworkInterface,
                        _write_buffer_size: usize,
                        _read_buffer_size: usize,
                        _channel_type: DataLinkChannelType)
    -> IoResult<(DataLinkSenderImpl, DataLinkReceiverImpl)> {
    // FIXME probably want one for each of send/recv
    let desc = NmDesc::new(network_interface);
    match desc {
        Ok(desc) => {
            let arc = Arc::new(desc);

            Ok((DataLinkSenderImpl { desc: arc.clone() },
                DataLinkReceiverImpl { desc: arc }))
        },
        Err(e) => Err(e)
    }
}

pub struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
}

impl<'a> DataLinkChannelIteratorImpl<'a> {
    pub fn next<'c>(&'c mut self) -> IoResult<EthernetHeader<'c>> {
        let desc = self.pc.desc.desc;
        let mut h: nm_pkthdr = unsafe { mem::uninitialized() };
        let mut buf = unsafe { nm_nextpkt(desc, &mut h) };
        if buf.is_null() {
            let mut fds = pollfd {
                fd: unsafe { NETMAP_FD(desc) },
                events: POLLIN,
                revents: 0,
            };
            if unsafe { poll(&mut fds, 1, -1) } < 0 {
                return Err(IoError::last_error());
            }
            buf = unsafe { nm_nextpkt(desc, &mut h) };
        }
        Ok(EthernetHeader::new( unsafe {
            mem::transmute(raw::Slice { data: buf, len: h.len as usize })
        }))
    }
}

