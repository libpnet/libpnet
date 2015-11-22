// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for sending and receiving data link layer packets

use std::io;
use std::option::Option;

use packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use util::NetworkInterface;

#[cfg(windows)]
#[path = "winpcap.rs"]
mod backend;

#[cfg(all(not(feature = "netmap"),
          target_os = "linux"
          )
      )]
#[path = "linux.rs"]
mod backend;

#[cfg(all(not(feature = "netmap"),
          any(target_os = "freebsd",
              target_os = "macos")
             )
     )]
#[path = "bpf.rs"]
mod backend;

#[cfg(feature = "netmap")]
#[path = "netmap.rs"]
mod backend;

/// Type of data link channel to present
#[derive(Clone, Copy)]
pub enum DataLinkChannelType {
    /// Send and receive layer 2 packets directly, including headers
    Layer2,
    /// Send and receive "cooked" packets - send and receive network layer packets
    /// FIXME Currently unimplemented
    Layer3(EtherType),
}

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
                        write_buffer_size: usize,
                        read_buffer_size: usize,
                        channel_type: DataLinkChannelType)
    -> io::Result<(Box<DataLinkSender>, Box<DataLinkReceiver>)> {
    backend::datalink_channel(network_interface,
                              write_buffer_size,
                              read_buffer_size,
                              channel_type)
}

/// Structure for sending packets at the data link layer. Should be constructed using
/// datalink_channel().
pub trait DataLinkSender : Send {
    /// Create and send a number of packets
    ///
    /// This will call `func` `num_packets` times. The function will be provided with a mutable
    /// packet to manipulate, which will then be sent. This allows packets to be built in-place,
    /// avoiding the copy required for `send`. If there is not sufficient capacity in the buffer,
    /// None will be returned.
    #[inline]
    fn build_and_send(&mut self,
                      num_packets: usize,
                      packet_size: usize,
                      func: &mut FnMut(MutableEthernetPacket))
        -> Option<io::Result<()>>;

    /// Send a packet
    ///
    /// This may require an additional copy compared to `build_and_send`, depending on the
    /// operating system being used. The second parameter is currently ignored, however `None`
    /// should be passed.
    #[inline]
    fn send_to(&mut self,
               packet: &EthernetPacket,
               dst: Option<NetworkInterface>)
        -> Option<io::Result<()>>;
}

/// Structure for receiving packets at the data link layer. Should be constructed using
/// datalink_channel().
pub trait DataLinkReceiver : Send {
    /// Returns an iterator over `EthernetPacket`s.
    ///
    /// This will likely be removed once other layer two types are supported.
    #[inline]
    fn iter<'a>(&'a mut self) -> Box<DataLinkChannelIterator + 'a>;
}

/// An iterator over data link layer packets
pub trait DataLinkChannelIterator<'a> {
    /// Get the next EthernetPacket in the channel
    #[inline]
    fn next(&mut self) -> io::Result<EthernetPacket>;
}
