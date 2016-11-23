extern crate libc;

use std::io;
use std::time::Duration;

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
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

pub fn duration_to_timespec(dur: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: dur.as_secs() as libc::time_t,
        tv_nsec: dur.subsec_nanos() as libc::c_long,
    }
}
