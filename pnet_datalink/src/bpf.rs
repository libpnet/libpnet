// Copyright (c) 2014-2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for sending and receiving data link layer packets using the /dev/bpf device.

extern crate libc;

use bindings::bpf;
use {DataLinkReceiver, DataLinkSender, NetworkInterface};

use pnet_sys;

use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

static ETHERNET_HEADER_SIZE: usize = 14;

/// The BPF-specific configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// The size of buffer to use when writing packets. Defaults to 4096.
    pub write_buffer_size: usize,

    /// The size of buffer to use when reading packets. Defaults to 4096.
    pub read_buffer_size: usize,

    /// The read timeout. Defaults to None.
    pub read_timeout: Option<Duration>,

    /// The write timeout. Defaults to None.
    pub write_timeout: Option<Duration>,

    /// The number of /dev/bpf* file descriptors to attempt before failing.
    ///
    /// This setting is only used on OS X - FreeBSD uses a single /dev/bpf rather than creating a
    /// new descriptor each time one is opened.
    ///
    /// Defaults to: 1000.
    pub bpf_fd_attempts: usize,
}

impl<'a> From<&'a super::Config> for Config {
    fn from(config: &super::Config) -> Config {
        Config {
            write_buffer_size: config.write_buffer_size,
            read_buffer_size: config.read_buffer_size,
            bpf_fd_attempts: config.bpf_fd_attempts,
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            bpf_fd_attempts: 1000,
            read_timeout: None,
            write_timeout: None,
        }
    }
}

/// Create a datalink channel using the /dev/bpf device
// NOTE buffer must be word aligned.
#[inline]
pub fn channel(network_interface: &NetworkInterface, config: Config) -> io::Result<super::Channel> {
    #[cfg(target_os = "freebsd")]
    fn get_fd(_attempts: usize) -> libc::c_int {
        unsafe {
            libc::open(
                CString::new(&b"/dev/bpf"[..]).unwrap().as_ptr(),
                libc::O_RDWR,
                0,
            )
        }
    }

    #[cfg(any(target_os = "openbsd", target_os = "macos", target_os = "ios"))]
    fn get_fd(attempts: usize) -> libc::c_int {
        for i in 0..attempts {
            let fd = unsafe {
                let file_name = format!("/dev/bpf{}", i);
                libc::open(
                    CString::new(file_name.as_bytes()).unwrap().as_ptr(),
                    libc::O_RDWR,
                    0,
                )
            };
            if fd != -1 {
                return fd;
            }
        }

        -1
    }

    #[cfg(target_os = "freebsd")]
    fn set_feedback(fd: libc::c_int) -> io::Result<()> {
        if unsafe { bpf::ioctl(fd, bpf::BIOCFEEDBACK, &1) } == -1 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "openbsd", target_os = "ios"))]
    fn set_feedback(_fd: libc::c_int) -> io::Result<()> {
        Ok(())
    }

    let fd = get_fd(config.bpf_fd_attempts);
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut iface: bpf::ifreq = unsafe { mem::zeroed() };
    for (i, c) in network_interface.name.bytes().enumerate() {
        iface.ifr_name[i] = c as i8;
    }

    let buflen = config.read_buffer_size as libc::c_uint;
    // NOTE Buffer length must be set before binding to an interface
    //      otherwise this will return Invalid Argument
    if unsafe { bpf::ioctl(fd, bpf::BIOCSBLEN, &buflen) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // Set the interface to use
    if unsafe { bpf::ioctl(fd, bpf::BIOCSETIF, &iface) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // Return from read as soon as packets are available - don't wait to fill the
    // buffer
    if unsafe { bpf::ioctl(fd, bpf::BIOCIMMEDIATE, &1) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    // Get the device type
    let mut dlt: libc::c_uint = 0;
    if unsafe { bpf::ioctl(fd, bpf::BIOCGDLT, &mut dlt) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    let mut loopback = false;
    let mut allocated_read_buffer_size = config.read_buffer_size;
    // The loopback device does weird things
    // FIXME This should really just be another L2 packet header type
    if dlt == bpf::DLT_NULL {
        loopback = true;
        // So we can guaranatee that we can have a header before the packet.
        // Loopback packets arrive without the header.
        allocated_read_buffer_size += ETHERNET_HEADER_SIZE;

        // Allow packets to be read back after they are written
        if let Err(e) = set_feedback(fd) {
            return Err(e);
        }
    } else {
        // Don't fill in source MAC
        if unsafe { bpf::ioctl(fd, bpf::BIOCSHDRCMPLT, &1) } == -1 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
    }

    // Enable nonblocking
    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            pnet_sys::close(fd);
        }
        return Err(err);
    }

    let fd = Arc::new(pnet_sys::FileDesc { fd: fd });
    let mut sender = Box::new(DataLinkSenderImpl {
        fd: fd.clone(),
        fd_set: unsafe { mem::zeroed() },
        write_buffer: vec![0; config.write_buffer_size],
        loopback: loopback,
        timeout: config
            .write_timeout
            .map(|to| pnet_sys::duration_to_timespec(to)),
    });
    unsafe {
        libc::FD_ZERO(&mut sender.fd_set as *mut libc::fd_set);
        libc::FD_SET(fd.fd, &mut sender.fd_set as *mut libc::fd_set);
    }
    let mut receiver = Box::new(DataLinkReceiverImpl {
        fd: fd.clone(),
        fd_set: unsafe { mem::zeroed() },
        read_buffer: vec![0; allocated_read_buffer_size],
        loopback: loopback,
        timeout: config
            .read_timeout
            .map(|to| pnet_sys::duration_to_timespec(to)),
        // Enough room for minimally sized packets without reallocating
        packets: VecDeque::with_capacity(allocated_read_buffer_size / 64),
    });
    unsafe {
        libc::FD_ZERO(&mut receiver.fd_set as *mut libc::fd_set);
        libc::FD_SET(fd.fd, &mut receiver.fd_set as *mut libc::fd_set);
    }

    Ok(super::Channel::Ethernet(sender, receiver))
}

struct DataLinkSenderImpl {
    fd: Arc<pnet_sys::FileDesc>,
    fd_set: libc::fd_set,
    write_buffer: Vec<u8>,
    loopback: bool,
    timeout: Option<libc::timespec>,
}

impl DataLinkSender for DataLinkSenderImpl {
    #[inline]
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        let len = num_packets * packet_size;
        if len >= self.write_buffer.len() {
            None
        } else {
            // If we're sending on the loopback device, discard the ethernet header.
            // The OS will prepend the packet with 4 bytes set to AF_INET.
            let offset = if self.loopback {
                ETHERNET_HEADER_SIZE
            } else {
                0
            };
            for chunk in self.write_buffer[..len].chunks_mut(packet_size) {
                func(chunk);
                let ret = unsafe {
                    libc::FD_SET(self.fd.fd, &mut self.fd_set as *mut libc::fd_set);
                    libc::pselect(
                        self.fd.fd + 1,
                        ptr::null_mut(),
                        &mut self.fd_set as *mut libc::fd_set,
                        ptr::null_mut(),
                        self.timeout
                            .as_ref()
                            .map(|to| to as *const libc::timespec)
                            .unwrap_or(ptr::null()),
                        ptr::null(),
                    )
                };
                if ret == -1 {
                    // Error occured!
                    return Some(Err(io::Error::last_os_error()));
                } else if ret == 0 {
                    return Some(Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")));
                } else {
                    match unsafe {
                        libc::write(
                            self.fd.fd,
                            chunk.as_ptr().offset(offset as isize) as *const libc::c_void,
                            (chunk.len() - offset) as libc::size_t,
                        )
                    } {
                        len if len == -1 => return Some(Err(io::Error::last_os_error())),
                        _ => (),
                    }
                }
            }
            Some(Ok(()))
        }
    }

    #[inline]
    fn send_to(&mut self, packet: &[u8], _dst: Option<NetworkInterface>) -> Option<io::Result<()>> {
        // If we're sending on the loopback device, discard the ethernet header.
        // The OS will prepend the packet with 4 bytes set to AF_INET.
        let offset = if self.loopback {
            ETHERNET_HEADER_SIZE
        } else {
            0
        };
        let ret = unsafe {
            libc::FD_SET(self.fd.fd, &mut self.fd_set as *mut libc::fd_set);
            libc::pselect(
                self.fd.fd + 1,
                ptr::null_mut(),
                &mut self.fd_set as *mut libc::fd_set,
                ptr::null_mut(),
                self.timeout
                    .as_ref()
                    .map(|to| to as *const libc::timespec)
                    .unwrap_or(ptr::null()),
                ptr::null(),
            )
        };
        if ret == -1 {
            // Error occured!
            return Some(Err(io::Error::last_os_error()));
        } else if ret == 0 {
            return Some(Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")));
        } else {
            match unsafe {
                libc::write(
                    self.fd.fd,
                    packet.as_ptr().offset(offset as isize) as *const libc::c_void,
                    (packet.len() - offset) as libc::size_t,
                )
            } {
                len if len == -1 => Some(Err(io::Error::last_os_error())),
                _ => Some(Ok(())),
            }
        }
    }
}

struct DataLinkReceiverImpl {
    fd: Arc<pnet_sys::FileDesc>,
    fd_set: libc::fd_set,
    read_buffer: Vec<u8>,
    loopback: bool,
    timeout: Option<libc::timespec>,
    packets: VecDeque<(usize, usize)>,
}

impl DataLinkReceiver for DataLinkReceiverImpl {
    fn next(&mut self) -> io::Result<&[u8]> {
        // Loopback packets arrive with a 4 byte header instead of normal ethernet header.
        // Discard that header and replace with zeroed out ethernet header.
        let (header_size, buffer_offset) = if self.loopback {
            (4, ETHERNET_HEADER_SIZE)
        } else {
            (0, 0)
        };
        if self.packets.is_empty() {
            let buffer = &mut self.read_buffer[buffer_offset..];
            let ret = unsafe {
                libc::FD_SET(self.fd.fd, &mut self.fd_set as *mut libc::fd_set);
                libc::pselect(
                    self.fd.fd + 1,
                    &mut self.fd_set as *mut libc::fd_set,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    self.timeout
                        .as_ref()
                        .map(|to| to as *const libc::timespec)
                        .unwrap_or(ptr::null()),
                    ptr::null(),
                )
            };
            if ret == -1 {
                return Err(io::Error::last_os_error());
            } else if ret == 0 {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"));
            } else {
                let buflen = match unsafe {
                    libc::read(
                        self.fd.fd,
                        buffer.as_ptr() as *mut libc::c_void,
                        buffer.len() as libc::size_t,
                    )
                } {
                    len if len > 0 => len,
                    _ => return Err(io::Error::last_os_error()),
                };
                let mut ptr = buffer.as_mut_ptr();
                let end = unsafe { buffer.as_ptr().offset(buflen as isize) };
                while (ptr as *const u8) < end {
                    unsafe {
                        let packet: *const bpf::bpf_hdr = mem::transmute(ptr);
                        let start =
                            ptr as isize + (*packet).bh_hdrlen as isize - buffer.as_ptr() as isize;
                        self.packets.push_back((
                            start as usize + header_size,
                            (*packet).bh_caplen as usize - header_size,
                        ));
                        let offset = (*packet).bh_hdrlen as isize + (*packet).bh_caplen as isize;
                        ptr = ptr.offset(bpf::BPF_WORDALIGN(offset));
                    }
                }
            }
        }
        let (start, mut len) = self.packets.pop_front().unwrap();
        len += buffer_offset;
        // Zero out part that will become fake ethernet header if on loopback.
        for i in (&mut self.read_buffer[start..start + buffer_offset]).iter_mut() {
            *i = 0;
        }
        Ok(&self.read_buffer[start..start + len])
    }
}

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<NetworkInterface> {
    #[path = "unix_interfaces.rs"]
    mod interfaces;
    interfaces::interfaces()
}
