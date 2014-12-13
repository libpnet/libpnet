// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for sending and receiving data link layer packets

use std::io::{IoResult};
use std::iter::Iterator;
use std::option::{Option};

use packet::ethernet::{EtherType, EthernetHeader, MutableEthernetHeader};
use util::NetworkInterface;

#[cfg(windows)]
#[path = "winpcap.rs"]
mod backend;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod backend;

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
#[path = "bpf.rs"]
mod backend;

/// Type of data link channel to present
pub enum DataLinkChannelType {
    /// Send and receive layer 2 packets directly, including headers
    Layer2,
    /// Send and receive "cooked" packets - send and receive network layer packets
    /// FIXME Currently unimplemented
    Layer3(EtherType)
}
impl Copy for DataLinkChannelType {}

/// Create a new (DataLinkSender, DataLinkReceiver) pair
///
/// This allows for sending and receiving packets at the data link layer.
///
/// A list of network interfaces can be retrieved using util::get_network_interfaces().
///
/// The buffer sizes should be large enough to handle the largest packet you wish
/// to send or receive. Note that these parameters may be ignored, depending on the operating
/// system.
///
/// The channel type specifies what layer to send and receive packets at, currently only layer 2 is
/// supported.
#[inline]
pub fn datalink_channel(network_interface: &NetworkInterface,
                        write_buffer_size: uint,
                        read_buffer_size: uint,
                        channel_type: DataLinkChannelType)
    -> IoResult<(DataLinkSender, DataLinkReceiver)> {
    match backend::datalink_channel(network_interface, write_buffer_size, read_buffer_size,
                                             channel_type) {
        Ok((tx, rx)) => Ok((DataLinkSender { dlsi: tx }, DataLinkReceiver { dlri: rx })),
        Err(e) => Err(e)
    }
}

/// Structure for sending packets at the data link layer. Should be constructed using
/// datalink_channel().
pub struct DataLinkSender {
    dlsi: backend::DataLinkSenderImpl
}

impl DataLinkSender {
    /// Create and send a number of packets
    ///
    /// This will call `func` `num_packets` times. The function will be provided with a mutable
    /// packet to manipulate, which will then be sent. This allows packets to be built in-place,
    /// avoiding the copy required for `send`. If there is not sufficient capacity in the buffer,
    /// None will be returned.
    #[inline]
    pub fn build_and_send(&mut self, num_packets: uint, packet_size: uint,
                          func: |MutableEthernetHeader| -> ()) -> Option<IoResult<()>> {
        self.dlsi.build_and_send(num_packets, packet_size, func)
    }

    /// Send a packet
    ///
    /// This may require an additional copy compared to `build_and_send`, depending on the
    /// operating system being used. The second parameter is currently ignored, however `None`
    /// should be passed.
    #[inline]
    pub fn send_to(&mut self, packet: EthernetHeader, dst: Option<NetworkInterface>)
        -> Option<IoResult<()>> {
        self.dlsi.send_to(packet, dst)
    }
}

/// Structure for receiving packets at the data link layer. Should be constructed using
/// datalink_channel().
pub struct DataLinkReceiver {
    dlri: backend::DataLinkReceiverImpl
}

impl DataLinkReceiver {
    /// Returns an iterator over `EthernetHeader`s.
    ///
    /// This will likely be removed once other layer two types are supported.
    #[inline]
    #[unstable]
    pub fn iter<'a>(&'a mut self) -> DataLinkChannelIterator<'a> {
        DataLinkChannelIterator {
            imp: self.dlri.iter()
        }
    }
}

/// An iterator over data link layer packets
pub struct DataLinkChannelIterator<'a> {
    imp: backend::DataLinkChannelIteratorImpl<'a>,
}

impl<'a> DataLinkChannelIterator<'a> {
    /// Get the next EthernetHeader in the channel
    #[inline]
    pub fn next<'c>(&'c mut self) -> IoResult<EthernetHeader<'c>> {
        self.imp.next()
    }
}

