// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate libc;

use std::io;
use std::mem;
use std::ptr;

pub const SOL_PACKET: libc::c_int = 263;
pub const SO_TIMESTAMPING: libc::c_int = 37;
pub const SIOCSHWTSTAMP: libc::c_ulong = 0x89b0;
pub const HWTSTAMP_TX_OFF: libc::c_int = 0;
pub const HWTSTAMP_FILTER_ALL: libc::c_int = 1;
pub const SOF_TIMESTAMPING_RX_HARDWARE: libc::c_uint = (1 << 2);
pub const SOF_TIMESTAMPING_RX_SOFTWARE: libc::c_uint = (1 << 3);
pub const MSG_DONTWAIT: libc::c_int = 0x0040;
pub const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
pub const PACKET_MR_PROMISC: libc::c_int = 1;

// man 7 packet
pub struct packet_mreq {
    pub mr_ifindex: libc::c_int,
    pub mr_type: libc::c_ushort,
    pub mr_alen: libc::c_ushort,
    pub mr_address: [libc::c_uchar; 8],
}

// man 7 netdevice
pub struct ifreq {
    pub ifr_name: [u8; 16],
    pub ifr_data: *mut libc::c_char
}

// man 3 cmsg
#[repr(C)]
pub struct cmsghdr {
    pub cmsg_len: libc::size_t,
    pub cmsg_level: libc::c_int,
    pub cmsg_type: libc::c_int,
}

// Kernel Documentation/networking/timestamping.txt
pub struct hwtstamp_config {
    pub flags: libc::c_int,
    pub tx_type: libc::c_int,
    pub rx_filter: libc::c_int,
}

#[cfg(not(windows))]
extern {
    pub fn ioctl(d: libc::c_int, request: libc::c_ulong, ...) -> libc::c_int;

    pub fn recvmsg(fd: libc::c_int, msg: *mut libc::msghdr, flags: libc::c_int) -> libc::ssize_t;
}

pub fn recv_msg(fd: libc::c_int, msg: *mut libc::msghdr, flags: libc::c_int) -> io::Result<usize> {
    let len = unsafe { recvmsg(fd, msg, flags) };
    if len < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(len as usize)
    }
}

// All of these are from socket.h
#[inline]
pub unsafe fn cmsg_firsthdr(msg: *const libc::msghdr) -> *const cmsghdr {
    if (*msg).msg_controllen >= (mem::size_of::<cmsghdr>() as libc::size_t) {
        mem::transmute((*msg).msg_control)
    } else {
        ptr::null()
    }
}

#[inline]
fn cmsg_align(len: usize) -> isize {
    let sz = mem::size_of::<libc::size_t>() as usize;
    ((len + sz - 1) & (!sz - 1)) as isize
}

#[inline]
pub unsafe fn cmsg_nexthdr(msg: *const libc::msghdr, cmsg: *const cmsghdr) -> *const cmsghdr {
    if (*cmsg).cmsg_len < (mem::size_of::<cmsghdr>() as libc::size_t) {
        return ptr::null();
    }
    let next_cmsg_ptr = (cmsg as *const libc::c_uchar).offset(cmsg_align((*cmsg).cmsg_len as usize))
                         as *const cmsghdr;
    let msghdr_end_addr = (msg as *const libc::c_uchar).offset((*msg).msg_controllen as isize);
    let next_cmsg_end_addr = next_cmsg_ptr.offset(1) as *const libc::c_uchar;
    let next_cmsg_align_end_addr = (cmsg as *const libc::c_uchar).offset(cmsg_align((*cmsg).cmsg_len as usize));
    if next_cmsg_end_addr > msghdr_end_addr || next_cmsg_align_end_addr > msghdr_end_addr {
        // We're done
        ptr::null()
    } else {
        // Return the entry
        next_cmsg_ptr
    }
}

#[inline]
pub unsafe fn cmsg_data(cmsg: *const cmsghdr) -> *const libc::c_uchar {
    cmsg.offset(1) as *const libc::c_uchar
}
