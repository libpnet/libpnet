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

pub const SOL_PACKET: libc::c_int = 263;
pub const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
pub const PACKET_MR_PROMISC: libc::c_int = 1;
pub const PACKET_AUXDATA: libc::c_int = 8;
pub const PACKET_FANOUT: libc::c_int = 18;
pub const PACKET_FANOUT_HASH: libc::c_int = 0;
pub const PACKET_FANOUT_LB: libc::c_int = 1;
pub const PACKET_FANOUT_CPU: libc::c_int = 2;
pub const PACKET_FANOUT_ROLLOVER: libc::c_int = 3;
pub const PACKET_FANOUT_RND: libc::c_int = 4;
pub const PACKET_FANOUT_QM: libc::c_int = 5;
pub const PACKET_FANOUT_CBPF: libc::c_int = 6;
pub const PACKET_FANOUT_EBPF: libc::c_int = 7;
pub const PACKET_FANOUT_FLAG_ROLLOVER: libc::c_uint = 0x1000;
#[allow(dead_code)] // following flag is unused yet
pub const PACKET_FANOUT_FLAG_UNIQUEID: libc::c_uint = 0x2000;
pub const PACKET_FANOUT_FLAG_DEFRAG: libc::c_uint = 0x8000;

// man 7 packet
#[repr(C)]
pub struct packet_mreq {
    pub mr_ifindex: libc::c_int,
    pub mr_type: libc::c_ushort,
    pub mr_alen: libc::c_ushort,
    pub mr_address: [libc::c_uchar; 8],
}

#[repr(C)]
pub struct tpacket_auxdata {
    pub tp_status: libc::c_uint,
    pub tp_len: libc::c_uint,
    pub tp_snaplen: libc::c_uint,
    pub tp_mac: libc::c_ushort,
    pub tp_net: libc::c_ushort,
    pub tp_vlan_tci: libc::c_ushort,
    pub tp_vlan_tpid: libc::c_ushort,
}

// struct tpacket_auxdata {
//     __u32 tp_status;
//     __u32 tp_len;      /* packet length */
//     __u32 tp_snaplen;  /* captured length */
//     __u16 tp_mac;
//     __u16 tp_net;
//     __u16 tp_vlan_tci;
//     __u16 tp_vlan_tpid; /* Since Linux 3.14; earlier, these
//                            were unused padding bytes */
// };
