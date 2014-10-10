/// FIXME: This can be removed when using Rust 0fd4f42 or newer

extern crate libc;

pub use libc::{c_uint, c_int, c_char, c_void, sockaddr, sockaddr_storage, socklen_t,
               setsockopt, IPPROTO_IP, socket, AF_INET, AF_INET6, c_uchar, c_ushort, bind,
               SOCK_DGRAM, sa_family_t};

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs,
    pub ifa_name: *mut c_char,
    pub ifa_flags: c_uint,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_ifu: *mut sockaddr, // FIXME This should be a union
    pub ifa_data: *mut c_void
}

#[cfg(target_os = "freebsd")]
#[repr(C)]
pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs,
    pub ifa_name: *mut c_char,
    pub ifa_flags: c_uint,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_dstaddr: *mut sockaddr,
    pub ifa_data: *mut c_void
}

#[cfg(target_os = "macos")]
#[repr(C)]
pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs,
    pub ifa_name: *mut c_char,
    pub ifa_flags: c_uint,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_dstaddr: *mut sockaddr,
    pub ifa_data: *mut c_void
}


#[cfg(target_os = "linux")]
#[repr(C)]
pub struct sockaddr_ll {
    pub sll_family: c_ushort,
    pub sll_protocol: c_ushort,
    pub sll_ifindex: c_int,
    pub sll_hatype: c_ushort,
    pub sll_pkttype: c_uchar,
    pub sll_halen: c_uchar,
    pub sll_addr: [c_uchar, ..8]
}

#[cfg(windows)]
pub const SOCK_RAW: c_int = 3;
#[cfg(windows)]
pub const IP_HDRINCL: c_int = 2;
#[cfg(windows)]
pub const IFF_LOOPBACK: c_int = 4;

#[cfg(target_os = "linux")]
pub const SOCK_RAW: c_int = 3;
#[cfg(target_os = "linux")]
pub const IP_HDRINCL: c_int = 3;
#[cfg(target_os = "linux")]
pub const IFF_LOOPBACK: c_int = 0x8;
#[cfg(target_os = "linux")]
pub const AF_PACKET : c_int = 17;

#[cfg(target_os = "freebsd")]
pub const SOCK_RAW: c_int = 3;
#[cfg(target_os = "freebsd")]
pub const IP_HDRINCL: c_int = 2;
#[cfg(target_os = "freebsd")]
pub const IFF_LOOPBACK: c_int = 0x8;

#[cfg(target_os = "macos")]
pub const SOCK_RAW: c_int = 3;
#[cfg(target_os = "macos")]
pub const IP_HDRINCL: c_int = 2;
#[cfg(target_os = "macos")]
pub const IFF_LOOPBACK: c_int = 0x8;

#[cfg(not(windows))]
extern "system" {
    pub fn getifaddrs(ifap: *mut *mut ifaddrs) -> c_int;
    pub fn freeifaddrs(ifa: *mut ifaddrs);
    pub fn if_nametoindex(ifname: *const c_char) -> c_uint;
}

