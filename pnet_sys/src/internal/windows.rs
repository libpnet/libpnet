extern crate libc;
extern crate winapi;

use std::io;

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
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
