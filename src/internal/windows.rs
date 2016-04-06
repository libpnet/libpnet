extern crate libc;

use std::io;

pub type CSocket = libc::SOCKET;
pub type BufLen = i32;


fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
}

pub unsafe fn close(sock: CSocket) {
    let _ = libc::closesocket(sock);
}

#[inline]
pub fn retry<F>(f: &mut F) -> libc::c_int
    where F: FnMut() -> libc::c_int
{
    loop {
        let minus1 = -1;
        let ret = f();
        if ret != minus1 || errno() as isize != libc::WSAEINTR as isize {
            return ret;
        }
    }
}
