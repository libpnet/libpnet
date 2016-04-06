extern crate libc;

use std::io;

pub type CSocket = libc::c_int;
pub type BufLen = libc::size_t;


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
