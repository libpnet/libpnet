extern crate libc;

use std::io;
use std::time::Duration;

pub type CSocket = libc::c_int;
pub type BufLen = libc::size_t;
pub type SockLen = libc::socklen_t;
pub type SockAddr = libc::sockaddr;
pub type SockAddrIn = libc::sockaddr_in;
pub type SockAddrStorage = libc::sockaddr_storage;
pub type In6Addr = libc::in6_addr;

pub const AF_INET: libc::c_int = libc::AF_INET;
pub const AF_INET6: libc::c_int = libc::AF_INET6;
pub const SOCK_RAW: libc::c_int = libc::SOCK_RAW;

pub const IPPROTO_IP: libc::c_int = libc::IPPROTO_IP;
pub const IP_HDRINCL: libc::c_int = libc::IP_HDRINCL;

pub const IFF_LOOPBACK: libc::c_int = libc::IFF_LOOPBACK;

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
}

pub unsafe fn close(sock: CSocket) {
    let _ = libc::close(sock);
}

#[inline]
pub fn retry<F>(f: &mut F) -> libc::ssize_t
    where F: FnMut() -> libc::ssize_t
{
    loop {
        let minus1 = -1;
        let ret = f();
        if ret != minus1 || errno() as isize != libc::EINTR as isize {
            return ret;
        }
    }
}

pub fn duration_to_timeval(dur: Duration) -> libc::timeval {
    libc::timeval {
        tv_sec: dur.as_secs() as libc::time_t,
        tv_usec: (dur.subsec_nanos() / 1_000) as libc::suseconds_t
    }
}

pub unsafe fn socket(af: libc::c_int, sock: libc::c_int, proto: libc::c_int) -> libc::c_int {
    libc::socket(af, sock, proto)
}

pub unsafe fn setsockopt(socket: libc::c_int, level: libc::c_int,
                         name: libc::c_int, value: *const libc::c_void,
                         option_len: libc::socklen_t) -> libc::c_int {
    libc::setsockopt(socket, level, name, value, option_len)
}
