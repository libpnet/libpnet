// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate libc;

pub static AF_LINK: libc::c_int = 18;

static IF_NAMESIZE: uint = 16;
static IFNAMSIZ: uint = IF_NAMESIZE;
static IOC_IN: libc::c_ulong = 0x80000000;
static IOC_OUT: libc::c_ulong = 0x40000000;
static IOC_INOUT: libc::c_ulong = IOC_IN | IOC_OUT;
static IOCPARM_SHIFT: libc::c_ulong = 13;
static IOCPARM_MASK: libc::c_ulong = (1 << (IOCPARM_SHIFT as uint)) - 1;

static SIZEOF_IFREQ: libc::c_ulong = 32;
static SIZEOF_C_UINT: libc::c_ulong = 4;
#[cfg(target_os = "freebsd")]
static SIZEOF_C_LONG: libc::c_int = 8;

pub static BIOCSETIF: libc::c_ulong = IOC_IN |
                                      ((SIZEOF_IFREQ & IOCPARM_MASK) << 16u) |
                                      ('B' as libc::c_ulong << 8u) |
                                      108;
pub static BIOCIMMEDIATE: libc::c_ulong = IOC_IN |
                                          ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) |
                                          ('B' as libc::c_ulong << 8) |
                                          112;
pub static BIOCGBLEN: libc::c_ulong = IOC_OUT |
                                      ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) |
                                      ('B' as libc::c_ulong << 8) |
                                      102;
pub static BIOCGDLT: libc::c_ulong = IOC_OUT |
                                      ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) |
                                      ('B' as libc::c_ulong << 8) |
                                      106;

pub static BIOCSBLEN: libc::c_ulong = IOC_INOUT |
                                      ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) |
                                      ('B' as libc::c_ulong << 8) |
                                      102;
pub static BIOCSHDRCMPLT: libc::c_ulong = IOC_IN |
                                          ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) |
                                          ('B' as libc::c_ulong << 8) |
                                          117;

#[cfg(target_os = "freebsd")]
pub static BIOCFEEDBACK: libc::c_ulong = IOC_IN |
                                          ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) |
                                          ('B' as libc::c_ulong << 8) |
                                          124;
// NOTE Could use BIOCSSEESENT on OS X, though set to 1 by default anyway

pub static DLT_NULL: libc::c_uint = 0;

#[cfg(target_os = "freebsd")]
static BPF_ALIGNMENT: libc::c_int = SIZEOF_C_LONG;
#[cfg(target_os = "macos")]
#[cfg(windows)]
static BPF_ALIGNMENT: libc::c_int = 4;

pub fn BPF_WORDALIGN<T : Int + ToPrimitive + FromPrimitive>(x: T) -> T {
    use std::num::{from_i32};
    let bpf_alignment: T = from_i32(BPF_ALIGNMENT).unwrap();
    let one: T = from_i32(1).unwrap();

    (x + (bpf_alignment - one)) & !(bpf_alignment - one)
}

// See /usr/include/net/if.h
pub struct ifreq {
    pub ifr_name: [libc::c_char, ..IFNAMSIZ],
    pub ifru_addr: libc::sockaddr, // NOTE Should be a union
}

// See /usr/include/net/if_dl.h
#[cfg(target_os = "freebsd")]
pub struct sockaddr_dl {
    pub sdl_len: libc::c_uchar,
    pub sdl_family: libc::c_uchar,
    pub sdl_index: libc::c_ushort,
    pub sdl_type: libc::c_uchar,
    pub sdl_nlen: libc::c_uchar,
    pub sdl_alen: libc::c_uchar,
    pub sdl_slen: libc::c_uchar,
    pub sdl_data: [libc::c_char, ..46],
}

#[cfg(target_os = "macos")]
pub struct sockaddr_dl {
    pub sdl_len: libc::c_uchar,
    pub sdl_family: libc::c_uchar,
    pub sdl_index: libc::c_ushort,
    pub sdl_type: libc::c_uchar,
    pub sdl_nlen: libc::c_uchar,
    pub sdl_alen: libc::c_uchar,
    pub sdl_slen: libc::c_uchar,
    pub sdl_data: [libc::c_char, ..12],
    pub sdl_rcf: libc::c_ushort,
    pub sdl_route: [libc::c_ushort, ..16],
}


// See man 4 bpf or /usr/include/net/bpf.h [windows: or Common/Packet32.h]
#[cfg(target_os = "freebsd")]
#[cfg(target_os = "macos", target_word_size = "32")]
#[cfg(windows)]
pub struct bpf_hdr {
    pub bh_tstamp: libc::timeval,
    pub bh_caplen: u32,
    pub bh_datalen: u32,
    pub bh_hdrlen: libc::c_ushort,
}

pub struct timeval32 {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

#[cfg(target_os = "macos", target_word_size = "64")]
pub struct bpf_hdr {
    pub bh_tstamp: timeval32,
    pub bh_caplen: u32,
    pub bh_datalen: u32,
    pub bh_hdrlen: libc::c_ushort,
}

#[cfg(not(windows))]
extern {
    pub fn ioctl(d: libc::c_int, request: libc::c_ulong, ...) -> libc::c_int;
}

