extern crate libc;
extern crate winapi;
extern crate ws2_32;

use std::io;
use std::time::Duration;

pub type CSocket = winapi::SOCKET;
pub type BufLen = i32;
pub type SockLen = winapi::socklen_t;
pub type SockAddr = winapi::SOCKADDR;
pub type SockAddrIn = winapi::SOCKADDR_IN;
pub type SockAddrStorage = winapi::SOCKADDR_STORAGE;
pub type In6Addr = winapi::in6_addr;

pub const AF_INET: libc::c_int = winapi::AF_INET;
pub const AF_INET6: libc::c_int = winapi::AF_INET6;
pub const SOCK_RAW: libc::c_int = winapi::SOCK_RAW;

pub const IPPROTO_IP: libc::c_int = winapi::IPPROTO_IP;
pub const IP_HDRINCL: libc::c_int = winapi::IP_HDRINCL;

pub const IFF_LOOPBACK: libc::c_int = 0x00000004;

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
}

pub unsafe fn close(sock: CSocket) {
    let _ = ws2_32::closesocket(sock);
}

#[inline]
pub fn retry<F>(f: &mut F) -> libc::c_int
    where F: FnMut() -> libc::c_int
{
    loop {
        let minus1 = -1;
        let ret = f();
        if ret != minus1 || errno() as isize != winapi::WSAEINTR as isize {
            return ret;
        }
    }
}

pub fn duration_to_timeval(dur: Duration) -> libc::timeval {
    libc::timeval {
        tv_sec: dur.as_secs() as libc::c_long,
        tv_usec: (dur.subsec_nanos() / 1_000) as libc::c_long
    }
}

pub unsafe fn socket(af: libc::c_int, sock: libc::c_int, proto: libc::c_int) -> winapi::SOCKET {
    ws2_32::socket(af, sock, proto)
}

pub unsafe fn setsockopt(socket: libc::c_int, level: libc::c_int,
                         name: libc::c_int, value: *const libc::c_void,
                         option_len: winapi::socklen_t) -> libc::c_int {
    ws2_32::setsockopt(socket, level, name, value, option_len)
}
