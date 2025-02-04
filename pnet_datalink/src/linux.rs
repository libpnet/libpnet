// Copyright (c) 2014-2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for sending and receiving data link layer packets using Linux's `AF_PACKET`.

extern crate libc;

use crate::bindings::linux;
use crate::{DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface, TpacketAuxdata};

// use libc::cmsghdr;
// use pnet_sys;

use std::fmt::Debug;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::raw::c_void;
use std::sync::Arc;
use std::time::Duration;

fn network_addr_to_sockaddr(
    ni: &NetworkInterface,
    storage: *mut libc::sockaddr_storage,
    proto: libc::c_int,
) -> usize {
    unsafe {
        let sll: *mut libc::sockaddr_ll = mem::transmute(storage);
        (*sll).sll_family = libc::AF_PACKET as libc::sa_family_t;
        if let Some(MacAddr(a, b, c, d, e, f)) = ni.mac {
            (*sll).sll_addr = [a, b, c, d, e, f, 0, 0];
        }
        (*sll).sll_protocol = (proto as u16).to_be();
        (*sll).sll_halen = 6;
        (*sll).sll_ifindex = ni.index as i32;
        mem::size_of::<libc::sockaddr_ll>()
    }
}

/// Configuration for the Linux datalink backend.
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

    /// Specifies whether to read packets at the datalink layer or network layer.
    /// NOTE FIXME Currently ignored.
    /// Defaults to Layer2.
    pub channel_type: super::ChannelType,

    /// Specifies packet fanout option, if desired. Defaults to None.
    pub fanout: Option<super::FanoutOption>,

    /// Promiscuous mode.
    pub promiscuous: bool,
    ///enable auxdata
    pub packet_auxdata: bool,

    pub socket_fd: Option<i32>,
}

impl<'a> From<&'a super::Config> for Config {
    fn from(config: &super::Config) -> Config {
        Config {
            write_buffer_size: config.write_buffer_size,
            read_buffer_size: config.read_buffer_size,
            channel_type: config.channel_type,
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
            fanout: config.linux_fanout,
            promiscuous: config.promiscuous,
            socket_fd: config.socket_fd,
            packet_auxdata: config.packet_auxdata,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: None,
            write_timeout: None,
            channel_type: super::ChannelType::Layer2,
            fanout: None,
            promiscuous: true,
            socket_fd: None,
            packet_auxdata: false,
        }
    }
}

/// Create a data link channel using the Linux's `AF_PACKET` socket type.
#[inline]
pub fn channel(network_interface: &NetworkInterface, config: Config) -> io::Result<super::Channel> {
    let (_typ, proto) = match config.channel_type {
        super::ChannelType::Layer2 => (libc::SOCK_RAW, libc::ETH_P_ALL),
        super::ChannelType::Layer3(proto) => (libc::SOCK_DGRAM, proto as i32),
    };

    let socket = match config.socket_fd {
        Some(sock) => sock,
        None => match unsafe { libc::socket(libc::AF_PACKET, _typ, proto.to_be()) } {
            -1 => return Err(io::Error::last_os_error()),
            fd => fd,
        },
    };

    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = network_addr_to_sockaddr(network_interface, &mut addr, proto);
    let send_addr = (&addr as *const libc::sockaddr_storage) as *const libc::sockaddr;
    // Bind to interface
    if unsafe { libc::bind(socket, send_addr, len as libc::socklen_t) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            pnet_sys::close(socket);
        }
        return Err(err);
    }

    let mut pmr: linux::packet_mreq = unsafe { mem::zeroed() };
    pmr.mr_ifindex = network_interface.index as i32;
    pmr.mr_type = linux::PACKET_MR_PROMISC as u16;

    // Enable promiscuous capture
    if config.promiscuous {
        if unsafe {
            libc::setsockopt(
                socket,
                linux::SOL_PACKET,
                linux::PACKET_ADD_MEMBERSHIP,
                (&pmr as *const linux::packet_mreq) as *const libc::c_void,
                mem::size_of::<linux::packet_mreq>() as libc::socklen_t,
            )
        } == -1
        {
            let err = io::Error::last_os_error();
            unsafe {
                pnet_sys::close(socket);
            }
            return Err(err);
        }
    }

    if config.packet_auxdata {
        if unsafe {
            const ONEVAL: libc::c_int = 1;
            let p_oneval = &ONEVAL as *const libc::c_int;
            libc::setsockopt(
                socket,
                linux::SOL_PACKET,
                linux::PACKET_AUXDATA,
                p_oneval as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        } == -1
        {
            let err = io::Error::last_os_error();
            unsafe {
                pnet_sys::close(socket);
            }
            return Err(err);
        }
    }

    // Enable packet fanout
    if let Some(fanout) = config.fanout {
        use super::FanoutType;
        let mut typ = match fanout.fanout_type {
            FanoutType::HASH => linux::PACKET_FANOUT_HASH,
            FanoutType::LB => linux::PACKET_FANOUT_LB,
            FanoutType::CPU => linux::PACKET_FANOUT_CPU,
            FanoutType::ROLLOVER => linux::PACKET_FANOUT_ROLLOVER,
            FanoutType::RND => linux::PACKET_FANOUT_RND,
            FanoutType::QM => linux::PACKET_FANOUT_QM,
            FanoutType::CBPF => linux::PACKET_FANOUT_CBPF,
            FanoutType::EBPF => linux::PACKET_FANOUT_EBPF,
        } as u32;
        // set defrag flag
        if fanout.defrag {
            typ = typ | linux::PACKET_FANOUT_FLAG_DEFRAG;
        }
        // set rollover flag
        if fanout.rollover {
            typ = typ | linux::PACKET_FANOUT_FLAG_ROLLOVER;
        }
        // set uniqueid flag -- probably not needed atm..
        // PACKET_FANOUT_FLAG_UNIQUEID -- https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4a69a864209e9ab436d4a58e8028ac96cc873d15
        let arg: libc::c_uint = fanout.group_id as u32 | (typ << 16);

        if unsafe {
            libc::setsockopt(
                socket,
                linux::SOL_PACKET,
                linux::PACKET_FANOUT,
                (&arg as *const libc::c_uint) as *const libc::c_void,
                mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        } == -1
        {
            let err = io::Error::last_os_error();
            unsafe {
                pnet_sys::close(socket);
            }
            return Err(err);
        }
    }

    // Enable nonblocking
    if unsafe { libc::fcntl(socket, libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            pnet_sys::close(socket);
        }
        return Err(err);
    }

    let fd = Arc::new(pnet_sys::FileDesc { fd: socket });
    let sender = Box::new(DataLinkSenderImpl {
        socket: fd.clone(),
        write_buffer: vec![0; config.write_buffer_size],
        _channel_type: config.channel_type,
        send_addr: unsafe { *(send_addr as *const libc::sockaddr_ll) },
        send_addr_len: len,
        timeout: config
            .write_timeout
            .map(|to| pnet_sys::duration_to_timespec(to)),
    });
    let receiver = Box::new(DataLinkReceiverImpl {
        socket: fd.clone(),
        read_buffer: vec![0; config.read_buffer_size],
        _channel_type: config.channel_type,
        timeout: config
            .read_timeout
            .map(|to| pnet_sys::duration_to_timespec(to)),
        enabled_packet_auxdata: config.packet_auxdata,
    });

    Ok(super::Channel::Ethernet(sender, receiver))
}

struct DataLinkSenderImpl {
    socket: Arc<pnet_sys::FileDesc>,
    write_buffer: Vec<u8>,
    _channel_type: super::ChannelType,
    send_addr: libc::sockaddr_ll,
    send_addr_len: usize,
    timeout: Option<libc::timespec>,
}

impl DataLinkSender for DataLinkSenderImpl {
    // FIXME Layer 3
    #[inline]
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        let len = num_packets * packet_size;
        if len <= self.write_buffer.len() {
            let min = std::cmp::min(self.write_buffer.len(), len);
            let mut_slice = &mut self.write_buffer;

            let mut pollfd = libc::pollfd {
                fd: self.socket.fd,
                events: libc::POLLOUT, // Monitoring for write ability
                revents: 0, // Will be filled by poll to indicate the events that occurred
            };

            // Convert timeout to milliseconds as required by poll
            let timeout_ms = self
                .timeout
                .as_ref()
                .map(|to| (to.tv_sec as i64 * 1000) + (to.tv_nsec as i64 / 1_000_000))
                .unwrap_or(-1); // -1 means wait indefinitely

            for chunk in mut_slice[..min].chunks_mut(packet_size) {
                func(chunk);
                let send_addr =
                    (&self.send_addr as *const libc::sockaddr_ll) as *const libc::sockaddr;

                let ret = unsafe {
                    libc::poll(
                        &mut pollfd as *mut libc::pollfd,
                        1,
                        timeout_ms as libc::c_int,
                    )
                };

                if ret == -1 {
                    return Some(Err(io::Error::last_os_error()));
                } else if ret == 0 {
                    return Some(Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")));
                } else if pollfd.revents & libc::POLLOUT != 0 {
                    if let Err(e) = pnet_sys::send_to(
                        self.socket.fd,
                        chunk,
                        send_addr,
                        self.send_addr_len as libc::socklen_t,
                    ) {
                        return Some(Err(e));
                    }
                } else {
                    return Some(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Unexpected poll event",
                    )));
                }
            }

            Some(Ok(()))
        } else {
            None
        }
    }

    #[inline]
    fn send_to(&mut self, packet: &[u8], _dst: Option<NetworkInterface>) -> Option<io::Result<()>> {
        let mut pollfd = libc::pollfd {
            fd: self.socket.fd,
            events: libc::POLLOUT, // Monitoring for write ability
            revents: 0,            // Will be filled by poll to indicate the events that occurred
        };

        // Convert timeout to milliseconds as required by poll
        let timeout_ms = self
            .timeout
            .as_ref()
            .map(|to| (to.tv_sec as i64 * 1000) + (to.tv_nsec as i64 / 1_000_000))
            .unwrap_or(-1); // -1 means wait indefinitely

        let ret = unsafe {
            libc::poll(
                &mut pollfd as *mut libc::pollfd,
                1,
                timeout_ms as libc::c_int,
            )
        };

        if ret == -1 {
            Some(Err(io::Error::last_os_error()))
        } else if ret == 0 {
            Some(Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")))
        } else if pollfd.revents & libc::POLLOUT != 0 {
            // POLLOUT is set, meaning the socket is ready for writing
            match pnet_sys::send_to(
                self.socket.fd,
                packet,
                (&self.send_addr as *const libc::sockaddr_ll) as *const _,
                self.send_addr_len as libc::socklen_t,
            ) {
                Err(e) => Some(Err(e)),
                Ok(_) => Some(Ok(())),
            }
        } else {
            Some(Err(io::Error::new(
                io::ErrorKind::Other,
                "Unexpected poll event",
            )))
        }
    }
}

struct DataLinkReceiverImpl {
    socket: Arc<pnet_sys::FileDesc>,
    read_buffer: Vec<u8>,
    _channel_type: super::ChannelType,
    timeout: Option<libc::timespec>,
    enabled_packet_auxdata: bool,
}

impl DataLinkReceiver for DataLinkReceiverImpl {
    fn next(&mut self) -> io::Result<&[u8]> {
        let mut caddr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut pollfd = libc::pollfd {
            fd: self.socket.fd,
            events: libc::POLLIN, // Monitoring for read availability
            revents: 0,
        };

        // Convert timeout to milliseconds as required by poll
        let timeout_ms = self
            .timeout
            .as_ref()
            .map(|to| (to.tv_sec as i64 * 1000) + (to.tv_nsec as i64 / 1_000_000))
            .unwrap_or(-1); // -1 means wait indefinitely

        let ret = unsafe {
            libc::poll(
                &mut pollfd as *mut libc::pollfd,
                1,
                timeout_ms as libc::c_int,
            )
        };

        if ret == -1 {
            Err(io::Error::last_os_error())
        } else if ret == 0 {
            Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"))
        } else if pollfd.revents & libc::POLLIN != 0 {
            // POLLIN is set, meaning the socket has data to be read
            let res = pnet_sys::recv_from(self.socket.fd, &mut self.read_buffer, &mut caddr);
            match res {
                Ok(len) => Ok(&self.read_buffer[0..len]),
                Err(e) => Err(e),
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Unexpected poll event",
            ))
        }
    }

    fn next_msg(&mut self) -> io::Result<(&[u8], Option<TpacketAuxdata>)> {
        let mut pollfd = libc::pollfd {
            fd: self.socket.fd,
            events: libc::POLLIN, // Monitoring for read availability
            revents: 0,
        };

        // Convert timeout to milliseconds as required by poll
        let timeout_ms = self
            .timeout
            .as_ref()
            .map(|to| (to.tv_sec as i64 * 1000) + (to.tv_nsec as i64 / 1_000_000))
            .unwrap_or(-1); // -1 means wait indefinitely

        let ret = unsafe {
            libc::poll(
                &mut pollfd as *mut libc::pollfd,
                1,
                timeout_ms as libc::c_int,
            )
        };

        if ret == -1 {
            Err(io::Error::last_os_error())
        } else if ret == 0 {
            Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"))
        } else if pollfd.revents & libc::POLLIN != 0 {
            // POLLIN is set, meaning the socket has data to be read
            //align buffer on stack, careful of total stack size though.
            #[repr(align(8))]
            struct Align8<T>(T);
            const CAPACITY: usize = 128;
            let mut controlbuffer = Align8([0_u8; CAPACITY]);
            let mut iovec = libc::iovec {
                iov_base: self.read_buffer.as_mut_ptr().cast::<c_void>(),
                iov_len: self.read_buffer.len(),
            };
            let inithdr = unsafe {
                let mut msghdr = MaybeUninit::<libc::msghdr>::zeroed().assume_init();
                msghdr.msg_flags = 0;
                msghdr.msg_name = std::ptr::null_mut();
                msghdr.msg_namelen = 0;
                msghdr.msg_control = controlbuffer.0.as_mut_ptr().cast::<libc::c_void>();
                msghdr.msg_controllen = controlbuffer.0.len().try_into().unwrap();
                msghdr.msg_iov = std::ptr::from_mut::<libc::iovec>(&mut iovec);
                msghdr.msg_iovlen = 1;
                Box::into_raw(Box::new(msghdr))
            };
            let res = pnet_sys::recv_msg(self.socket.fd, inithdr);
            match res {
                Ok(len) => {
                    let mut auxdata: Option<TpacketAuxdata> = None;
                    if self.enabled_packet_auxdata {
                        //we know there should be just one single cmsg because the only option we enabled was auxdata
                        let is_auxpacket_data;
                        let current_hdr = unsafe {
                            let newhdr = libc::CMSG_FIRSTHDR(inithdr);
                            let hdrtmp = *newhdr;
                            is_auxpacket_data = hdrtmp.cmsg_type == linux::PACKET_AUXDATA
                                && hdrtmp.cmsg_level == linux::SOL_PACKET;
                            newhdr
                        };

                        if is_auxpacket_data {
                            const TPACKDATALEN: usize = mem::size_of::<linux::tpacket_auxdata>();
                            let tpacket = unsafe {
                                let data = libc::CMSG_DATA(current_hdr);
                                let slice = std::ptr::slice_from_raw_parts(data, TPACKDATALEN);
                                TpacketAuxdata::from(slice.as_ref().unwrap())
                            };
                            auxdata = Some(tpacket);
                        } else {
                            println!("bug in code, we should find this always.");
                        }
                    }
                    Ok((&self.read_buffer[0..len], auxdata))
                }
                Err(e) => Err(e),
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Unexpected poll event",
            ))
        }
    }
}

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<NetworkInterface> {
    #[path = "unix_interfaces.rs"]
    mod interfaces;
    interfaces::interfaces()
}
