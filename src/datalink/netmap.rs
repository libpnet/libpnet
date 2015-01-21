// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(bad_style)]

extern crate "rust-netmap" as netmap;
extern crate libc;

use libc::{c_void, size_t, c_int, c_ulong, c_short};
use self::netmap::netmap_user::{nm_open, nm_inject, nm_close, nm_nextpkt, nm_desc, nm_pkthdr,
                                NETMAP_FD};

use std::ffi::CString;
use std::io::{IoResult, IoError};
use std::mem;
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

type nfds_t = c_ulong;

extern {
    fn poll(fds: *mut pollfd, nfds: nfds_t, timeout: c_int) -> c_int;
}

struct NmDesc {
    desc: *mut nm_desc,
}

impl NmDesc {
    fn new(iface: &NetworkInterface) -> IoResult<NmDesc> {
        let ifname = CString::from_slice(iface.name.as_bytes());
        let desc = unsafe {
            nm_open(ifname.as_ptr(), ptr::null(), 0, ptr::null())
        };

        if desc.is_null() {
            Err(IoError::last_error())
        } else {
            Ok(NmDesc {
                desc: desc
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
    // FIXME This is incredibly inefficient
    pub fn build_and_send<F>(&mut self, num_packets: usize, packet_size: usize,
                          func: &mut F) -> Option<IoResult<()>>
        where F : FnMut(MutableEthernetHeader)
    {
        for _ in range(0, num_packets) {
            let mut vec: Vec<u8> = Vec::with_capacity(packet_size);
            {
                let meh = MutableEthernetHeader::new(vec.as_mut_slice());
                func(meh);
            }

            if let None = self.send_to(EthernetHeader::new(vec.as_slice()), None) {
                // FIXME This is wrong
                return None;
            }
        }

        Some(Ok(()))
    }

    pub fn send_to(&mut self, packet: EthernetHeader, _dst: Option<NetworkInterface>)
        -> Option<IoResult<()>> {
        if unsafe {
               nm_inject(self.desc.desc,
                         packet.packet().as_ptr() as *const c_void,
                         packet.packet().len() as size_t)
           } > 0 {
            Some(Ok(()))
        } else {
            // FIXME This is wrong
            None
        }
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
        let mut fds = pollfd {
            fd: unsafe { NETMAP_FD(self.pc.desc.desc) },
            events: POLLIN,
            revents: 0,
        };
        // FIXME Don't do this with each call
        // FIXME Check error code
        // FIXME epoll/kqueue
        unsafe { poll(&mut fds, 1, -1) };
        let mut h: nm_pkthdr = unsafe { mem::zeroed() };
        let buf = unsafe { nm_nextpkt(self.pc.desc.desc, &mut h) };
        if buf.is_null() {
            // FIXME Doesn't mean there's an error
            return Err(IoError::last_error());
        }
        Ok(EthernetHeader::new( unsafe {
            mem::transmute(raw::Slice { data: buf, len: h.len as usize })
        }))
    }
}

