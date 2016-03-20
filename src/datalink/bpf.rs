// Copyright (c) 2014-2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;

use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::iter::repeat;
use std::mem;
use std::sync::Arc;

use bindings::bpf;
use packet::Packet;
use packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use datalink::{EthernetDataLinkChannelIterator, DataLinkChannelType, EthernetDataLinkReceiver,
               EthernetDataLinkSender};
use datalink::DataLinkChannelType::{Layer2, Layer3};
use internal;
use util::NetworkInterface;

// NOTE buffer must be word aligned.
#[inline]
pub fn datalink_channel(network_interface: &NetworkInterface,
                        write_buffer_size: usize,
                        read_buffer_size: usize,
                        channel_type: DataLinkChannelType)
    -> io::Result<(Box<EthernetDataLinkSender>, Box<EthernetDataLinkReceiver>)> {
    #[cfg(target_os = "freebsd")]
    fn get_fd() -> libc::c_int {
        unsafe {
            libc::open(CString::new(&b"/dev/bpf"[..]).unwrap().as_ptr(),
                       libc::O_RDWR,
                       0)
        }
    }

    #[cfg(target_os = "macos")]
    fn get_fd() -> libc::c_int {
        // FIXME This is an arbitrary number of attempts
        for i in 0..1_000isize {
            let fd = unsafe {
                let file_name = format!("/dev/bpf{}", i);
                libc::open(CString::new(file_name.as_bytes()).unwrap().as_ptr(),
                           libc::O_RDWR,
                           0)
            };
            if fd != -1 {
                return fd;
            }
        }

        -1
    }

    #[cfg(target_os = "freebsd")]
    fn set_feedback(fd: libc::c_int) -> io::Result<()> {
        let one: libc::c_uint = 1;
        if unsafe { bpf::ioctl(fd, bpf::BIOCFEEDBACK, &one) } == -1 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn set_feedback(_fd: libc::c_int) -> io::Result<()> {
        Ok(())
    }

    match channel_type {
        Layer2 => (),
        Layer3(_) => unimplemented!(),
    }

    let fd = get_fd();
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut iface: bpf::ifreq = unsafe { mem::zeroed() };
    for (i, c) in network_interface.name.bytes().enumerate() {
        iface.ifr_name[i] = c as i8;
    }

    let buflen = read_buffer_size as libc::c_uint;
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
    let one: libc::c_uint = 1;
    if unsafe { bpf::ioctl(fd, bpf::BIOCIMMEDIATE, &one) } == -1 {
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
    let mut allocated_read_buffer_size = read_buffer_size;
    // The loopback device does weird things
    // FIXME This should really just be another L2 packet header type
    if dlt == bpf::DLT_NULL {
        loopback = true;
        // So we can guaranatee that we can have a header before the packet.
        // Loopback packets arrive without the header.
        allocated_read_buffer_size += EthernetPacket::minimum_packet_size();

        // Allow packets to be read back after they are written
        if let Err(e) = set_feedback(fd) {
            return Err(e);
        }
    } else {
        // Don't fill in source MAC
        if unsafe { bpf::ioctl(fd, bpf::BIOCSHDRCMPLT, &one) } == -1 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
    }

    let fd = Arc::new(internal::FileDesc { fd: fd });
    let sender = Box::new(DataLinkSenderImpl {
        fd: fd.clone(),
        write_buffer: repeat(0u8).take(write_buffer_size).collect(),
        loopback: loopback,
    });
    let receiver = Box::new(DataLinkReceiverImpl {
        fd: fd,
        read_buffer: repeat(0u8).take(allocated_read_buffer_size).collect(),
        loopback: loopback,
    });

    Ok((sender, receiver))
}

pub struct DataLinkSenderImpl {
    fd: Arc<internal::FileDesc>,
    write_buffer: Vec<u8>,
    loopback: bool,
}

impl EthernetDataLinkSender for DataLinkSenderImpl {
    #[inline]
    fn build_and_send(&mut self,
                      num_packets: usize,
                      packet_size: usize,
                      func: &mut FnMut(MutableEthernetPacket))
                      -> Option<io::Result<()>> {
        let len = num_packets * packet_size;
        if len >= self.write_buffer.len() {
            None
        } else {
            // If we're sending on the loopback device, discard the ethernet header.
            // The OS will prepend the packet with 4 bytes set to AF_INET.
            let offset = if self.loopback {
                MutableEthernetPacket::minimum_packet_size()
            } else {
                0
            };
            for chunk in self.write_buffer[..len].chunks_mut(packet_size) {
                {
                    let eh = MutableEthernetPacket::new(chunk).unwrap();
                    func(eh);
                }
                match unsafe {
                    libc::write(self.fd.fd,
                                chunk.as_ptr().offset(offset as isize) as *const libc::c_void,
                                (chunk.len() - offset) as libc::size_t)
                } {
                    len if len == -1 => return Some(Err(io::Error::last_os_error())),
                    _ => (),
                }
            }
            Some(Ok(()))
        }
    }

    #[inline]
    fn send_to(&mut self,
               packet: &EthernetPacket,
               _dst: Option<NetworkInterface>)
               -> Option<io::Result<()>> {
        // If we're sending on the loopback device, discard the ethernet header.
        // The OS will prepend the packet with 4 bytes set to AF_INET.
        let offset = if self.loopback {
            MutableEthernetPacket::minimum_packet_size()
        } else {
            0
        };
        match unsafe {
            libc::write(self.fd.fd,
                        packet.packet().as_ptr().offset(offset as isize) as *const libc::c_void,
                        (packet.packet().len() - offset) as libc::size_t)
        } {
            len if len == -1 => Some(Err(io::Error::last_os_error())),
            _ => Some(Ok(())),
        }
    }
}

pub struct DataLinkReceiverImpl {
    fd: Arc<internal::FileDesc>,
    read_buffer: Vec<u8>,
    loopback: bool,
}

impl EthernetDataLinkReceiver for DataLinkReceiverImpl {
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a> {
        let buflen = self.read_buffer.len();
        Box::new(DataLinkChannelIteratorImpl {
            pc: self,
            // Enough room for minimally sized packets without reallocating
            packets: VecDeque::with_capacity(buflen / 64),
        })
    }
}

pub struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
    packets: VecDeque<(usize, usize)>,
}

impl<'a> EthernetDataLinkChannelIterator<'a> for DataLinkChannelIteratorImpl<'a> {
    fn next(&mut self) -> io::Result<EthernetPacket> {
        // Loopback packets arrive with a 4 byte header instead of normal ethernet header.
        // Discard that header and replace with zeroed out ethernet header.
        let (header_size, buffer_offset) = if self.pc.loopback {
            (4, EthernetPacket::minimum_packet_size())
        } else {
            (0, 0)
        };
        if self.packets.is_empty() {
            let buffer = &mut self.pc.read_buffer[buffer_offset..];
            let buflen = match unsafe {
                libc::read(self.pc.fd.fd,
                           buffer.as_ptr() as *mut libc::c_void,
                           buffer.len() as libc::size_t)
            } {
                len if len > 0 => len,
                _ => return Err(io::Error::last_os_error()),
            };
            let mut ptr = buffer.as_mut_ptr();
            let end = unsafe { buffer.as_ptr().offset(buflen as isize) };
            while (ptr as *const u8) < end {
                unsafe {
                    let packet: *const bpf::bpf_hdr = mem::transmute(ptr);
                    let start = ptr as isize + (*packet).bh_hdrlen as isize -
                                buffer.as_ptr() as isize;
                    self.packets.push_back((start as usize + header_size,
                                            (*packet).bh_caplen as usize - header_size));
                    let offset = (*packet).bh_hdrlen as isize + (*packet).bh_caplen as isize;
                    ptr = ptr.offset(bpf::BPF_WORDALIGN(offset));
                }
            }
        }
        let (start, mut len) = self.packets.pop_front().unwrap();
        len += buffer_offset;
        // Zero out part that will become fake ethernet header if on loopback.
        for i in (&mut self.pc.read_buffer[start..start + buffer_offset]).iter_mut() {
            *i = 0;
        }
        Ok(EthernetPacket::new(&self.pc.read_buffer[start..start + len]).unwrap())
    }
}
