// Copyright (c) 2015-2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for sending and receiving data link layer packets using the netmap library

#![allow(bad_style)]

extern crate netmap_sys;
extern crate libc;

use self::netmap_sys::netmap_user::{NETMAP_BUF, NETMAP_FD, NETMAP_TXRING, nm_close, nm_desc,
                                    nm_nextpkt, nm_open, nm_pkthdr, nm_ring_next};
use self::netmap_sys::netmap::{netmap_slot, nm_ring_empty};

use std::ffi::CString;
use std::path::Path;
use std::fs::File;
use std::io;
use std::io::Read;
use std::mem;
use std::ptr;
use std::slice;
use std::sync::Arc;

use datalink::{self, NetworkInterface};
use datalink::Channel::Ethernet;
use datalink::{EthernetDataLinkChannelIterator, EthernetDataLinkReceiver, EthernetDataLinkSender};
use packet::Packet;
use packet::ethernet::{EthernetPacket, MutableEthernetPacket};

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
#[repr(C)]
struct pollfd {
    fd: libc::c_int,
    events: libc::c_short,
    revents: libc::c_short,
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const POLLIN: libc::c_short = 0x0001;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const POLLOUT: libc::c_short = 0x0004;

#[cfg(target_os = "freebsd")]
type nfds_t = libc::c_uint;
#[cfg(target_os = "linux")]
type nfds_t = libc::c_ulong;

extern {
    fn poll(fds: *mut pollfd, nfds: nfds_t, timeout: libc::c_int) -> libc::c_int;
    fn ppoll(fds: *mut pollfd, nfds: nfds_t, timeout: *const libc::timespec, newsigmask: *const libc::sigset_t) -> libc::c_int;
}

struct NmDesc {
    desc: *mut nm_desc,
    buf_size: libc::c_uint,
}

unsafe impl Send for NmDesc {}
unsafe impl Sync for NmDesc {}

impl NmDesc {
    fn new(iface: &NetworkInterface) -> io::Result<NmDesc> {
        let ifname = CString::new(("netmap:".to_owned() + &iface.name[..]).as_bytes());
        let desc = unsafe { nm_open(ifname.unwrap().as_ptr(), ptr::null(), 0, ptr::null()) };

        if desc.is_null() {
            Err(io::Error::last_os_error())
        } else {
            let mut f = try!(File::open(&Path::new("/sys/module/netmap/parameters/buf_size")));
            let mut num_str = String::new();
            try!(f.read_to_string(&mut num_str));
            let buf_size = num_str.trim_right().parse().unwrap();

            Ok(NmDesc {
                desc: desc,
                buf_size: buf_size,
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

/// Netmap specific configuration
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// The read timeout. Defaults to None.
    pub read_timeout: Option<Duration>,

    /// The write timeout. Defaults to None.
    pub write_timeout: Option<Duration>,
}

impl<'a> From<&'a datalink::Config> for Config {
    fn from(_config: &datalink::Config) -> Config {
        Config {
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            read_timeout: None,
            write_timeout: None,
        }
    }
}

#[inline]
fn get_timeout(to: Option<Duration>) -> *const libc::timespec {
    match to {
        Some(to) => &libc::timespec {
            tv_sec: to.as_secs() as libc::time_t,
            tv_nsec: to.subsec_nanos() as libc::c_long
        } as *const libc::timespec,
        None => ptr::null()
    }
}

/// Create a datalink channel using the netmap library
#[inline]
pub fn channel(network_interface: &NetworkInterface, config: &Config)
    -> io::Result<datalink::Channel> {
    // FIXME probably want one for each of send/recv
    let desc = NmDesc::new(network_interface);
    match desc {
        Ok(desc) => {
            let arc = Arc::new(desc);

            Ok(Ethernet(
                Box::new(DataLinkSenderImpl {
                    desc: arc.clone(),
                    timeout: get_timeout(config.write_timeout)
                }),
                Box::new(DataLinkReceiverImpl {
                    desc: arc,
                    timeout: get_timeout(config.read_timeout)
                })))
        }
        Err(e) => Err(e),
    }
}

struct DataLinkSenderImpl {
    desc: Arc<NmDesc>,
    timeout: *const libc::timespec,
}

impl EthernetDataLinkSender for DataLinkSenderImpl {
    #[inline]
    fn build_and_send(&mut self,
                      num_packets: usize,
                      packet_size: usize,
                      func: &mut FnMut(MutableEthernetPacket))
        -> Option<io::Result<()>> {
        assert!(packet_size <= self.desc.buf_size as usize);
        let desc = self.desc.desc;
        let mut fds = pollfd {
            fd: unsafe { NETMAP_FD(desc) },
            events: POLLOUT,
            revents: 0,
        };
        let mut packet_idx = 0usize;
        while packet_idx < num_packets {
            unsafe {
                if ppoll(&mut fds, 1, self.timeout, ptr::null()) < 0 {
                    return Some(Err(io::Error::last_os_error()));
                }
                let ring = NETMAP_TXRING((*desc).nifp, 0);
                while !nm_ring_empty(ring) && packet_idx < num_packets {
                    let i = (*ring).cur;
                    let slot_ptr: *mut netmap_slot = mem::transmute(&mut (*ring).slot);
                    let buf = NETMAP_BUF(ring, (*slot_ptr.offset(i as isize)).buf_idx as isize);
                    let slice = slice::from_raw_parts_mut(buf as *mut u8, packet_size);
                    let meh = MutableEthernetPacket::new(slice).unwrap();
                    (*slot_ptr.offset(i as isize)).len = packet_size as u16;
                    func(meh);
                    let next = nm_ring_next(ring, i);
                    (*ring).head = next;
                    (*ring).cur = next;
                    packet_idx += 1;
                }
            }
        }

        Some(Ok(()))
    }

    #[inline]
    fn send_to(&mut self,
               packet: &EthernetPacket,
               _dst: Option<NetworkInterface>)
        -> Option<io::Result<()>> {
        use packet::MutablePacket;
        self.build_and_send(1,
                            packet.packet().len(),
                            &mut |mut eh: MutableEthernetPacket| {
                                eh.clone_from(packet);
                            })
    }
}

struct DataLinkReceiverImpl {
    desc: Arc<NmDesc>,
    timeout: *const libc::timespec,
}

impl EthernetDataLinkReceiver for DataLinkReceiverImpl {
    // FIXME Layer 3
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a> {
        Box::new(DataLinkChannelIteratorImpl { pc: self })
    }
}

struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
}

impl<'a> EthernetDataLinkChannelIterator<'a> for DataLinkChannelIteratorImpl<'a> {
    fn next(&mut self) -> io::Result<EthernetPacket> {
        let desc = self.pc.desc.desc;
        let mut h: nm_pkthdr = unsafe { mem::uninitialized() };
        let mut buf = unsafe { nm_nextpkt(desc, &mut h) };
        if buf.is_null() {
            let mut fds = pollfd {
                fd: unsafe { NETMAP_FD(desc) },
                events: POLLIN,
                revents: 0,
            };
            if unsafe { ppoll(&mut fds, 1, self.timeout, ptr::null()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            buf = unsafe { nm_nextpkt(desc, &mut h) };
        }
        Ok(EthernetPacket::new(unsafe {
            slice::from_raw_parts(buf, h.len as usize)
        }).unwrap())
    }
}

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<NetworkInterface> {
    #[path = "unix_interfaces.rs"]
    mod interfaces;
    interfaces::interfaces()
}
