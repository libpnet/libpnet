// Copyright (c) 2016 Linus Färnstrand <faern@faern.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for sending and receiving data link layer packets on a fake network managed
//! by in memory FIFO queues. Useful for writing tests.

use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time;

use datalink::{self, EthernetDataLinkChannelIterator, EthernetDataLinkReceiver,
               EthernetDataLinkSender, NetworkInterface};
use packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use packet::Packet;
use util::MacAddr;

/// Configuration for the dummy datalink backend. Contains `std::sync::mpsc`
/// channels that are used to communicate with the fake network.
#[derive(Debug)]
pub struct Config {
    /// The fake network will pull packets (or errors) form this `Receiver`
    pub in_packets_rx: Receiver<io::Result<Box<[u8]>>>,

    in_packets_tx: Option<Sender<io::Result<Box<[u8]>>>>,

    /// All packets sent to this fake network will end up on this `Sender`
    pub out_packets_tx: Sender<Box<[u8]>>,

    out_packets_rx: Option<Receiver<Box<[u8]>>>,
}

impl Config {
    /// Get the `Sender` handle that can inject packets in the fake network
    pub fn inject_handle(&mut self) -> Option<Sender<io::Result<Box<[u8]>>>> {
        self.in_packets_tx.take()
    }

    /// Get the `Receiver` handle where packets sent to the fake network can be read
    pub fn read_handle(&mut self) -> Option<Receiver<Box<[u8]>>> {
        self.out_packets_rx.take()
    }
}

impl<'a> From<&'a datalink::Config> for Config {
    /// This conversion will not allow injecting and reading packets from the dummy network.
    /// To do that please create your own `dummy::Config`
    fn from(_config: &datalink::Config) -> Config {
        Config::default()
    }
}

impl Default for Config {
    /// This conversion will not allow injecting and reading packets from the dummy network.
    /// To do that please create your own `dummy::Config`
    fn default() -> Config {
        let (in_tx, in_rx) = mpsc::channel();
        let (out_tx, out_rx) = mpsc::channel();
        Config {
            in_packets_rx: in_rx,
            in_packets_tx: Some(in_tx),
            out_packets_tx: out_tx,
            out_packets_rx: Some(out_rx),
        }
    }
}

/// Create a data link channel backed by FIFO queues. Useful for debugging and testing.
pub fn channel(_: &NetworkInterface, config: Config) -> io::Result<datalink::Channel> {
    let sender = Box::new(MockEthernetDataLinkSender { out_packets: config.out_packets_tx });
    let receiver =
        Box::new(MockEthernetDataLinkReceiver { in_packets: Some(config.in_packets_rx) });

    Ok(datalink::Channel::Ethernet(sender, receiver))
}


struct MockEthernetDataLinkSender {
    out_packets: Sender<Box<[u8]>>,
}

impl EthernetDataLinkSender for MockEthernetDataLinkSender {
    fn build_and_send(&mut self,
                      num_packets: usize,
                      packet_size: usize,
                      func: &mut FnMut(MutableEthernetPacket))
        -> Option<io::Result<()>> {
        for _ in 0..num_packets {
            let mut buffer = vec![0; packet_size];
            {
                let pkg = match MutableEthernetPacket::new(&mut buffer[..]) {
                    Some(pkg) => pkg,
                    None => return None,
                };
                func(pkg);
            }
            // Send the data to the queue. Don't care if it's closed
            self.out_packets.send(buffer.into_boxed_slice()).unwrap_or(());
        }
        Some(Ok(()))
    }

    fn send_to(&mut self,
               packet: &EthernetPacket,
               _dst: Option<NetworkInterface>)
        -> Option<io::Result<()>> {
        let buffer = packet.packet().to_vec();
        self.out_packets.send(buffer.into_boxed_slice()).unwrap_or(());
        Some(Ok(()))
    }
}

struct MockEthernetDataLinkReceiver {
    in_packets: Option<Receiver<io::Result<Box<[u8]>>>>,
}

impl EthernetDataLinkReceiver for MockEthernetDataLinkReceiver {
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a> {
        Box::new(MockEthernetDataLinkChannelIterator {
            in_packets: self.in_packets.take().expect("Only one receiver allowed"),
            used_packets: vec![],
        })
    }
}

struct MockEthernetDataLinkChannelIterator {
    in_packets: Receiver<io::Result<Box<[u8]>>>,
    used_packets: Vec<Box<[u8]>>,
}

impl<'a> EthernetDataLinkChannelIterator<'a> for MockEthernetDataLinkChannelIterator {
    fn next(&mut self) -> io::Result<EthernetPacket> {
        match self.in_packets.recv() {
            Ok(result) => {
                // A network event happened. Might be a packet or a simulated error
                match result {
                    Ok(buffer) => {
                        self.used_packets.push(buffer);
                        let buffer_ref = &*self.used_packets[self.used_packets.len() - 1];
                        let packet = EthernetPacket::new(buffer_ref).unwrap();
                        Ok(packet)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(_) => {
                // The channel supplying fake packets is broken. The user lost/destroyed their
                // inject_handle. This means there will never be any more packets sent to this
                // dummy network. To simulate an idle network we block and sleep forever here.
                loop {
                    thread::sleep(time::Duration::new(::std::u64::MAX, 0));
                }
            }
        }
    }
}

/// Get three fake interfaces generated with `dummy_interface`.
pub fn interfaces() -> Vec<NetworkInterface> {
    (0..3).map(|i| dummy_interface(i)).collect()
}

/// Generates a fake `NetworkInterface`.
/// The name of the interface will be `ethX` where X is the integer `i`.
/// The index will be `i`.
/// The MAC will be `01:02:03:04:05:i`.
pub fn dummy_interface(i: u8) -> NetworkInterface {
    NetworkInterface {
        name: format!("eth{}", i),
        index: i as u32,
        mac: Some(MacAddr::new(1, 2, 3, 4, 5, i)),
        ips: None,
        flags: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
    use std::io;
    use std::thread::{sleep, spawn};
    use std::time::Duration;

    use packet::{MutablePacket, Packet};
    use packet::ethernet::EthernetPacket;
    use datalink::{EthernetDataLinkReceiver, EthernetDataLinkSender};
    use datalink::Channel::Ethernet;

    #[test]
    fn send_too_small_packet_size() {
        let (_, read_handle, mut tx, _) = create_net();
        // Check that it fails to send with too small packet sizes
        assert!(tx.build_and_send(1, 0, &mut |_| {}).is_none());
    }

    #[test]
    fn send_nothing() {
        let (_, read_handle, mut tx, _) = create_net();
        // Check that sending zero packets yields zero packets
        tx.build_and_send(0,
                            20,
                            &mut |_| {
                                panic!("Should not be called");
                            })
            .unwrap()
            .unwrap();
        assert!(read_handle.try_recv().is_err());
    }

    #[test]
    fn send_one_packet() {
        let (_, read_handle, mut tx, _) = create_net();
        // Check that sending one packet yields one packet
        tx.build_and_send(1,
                            20,
                            &mut |mut pkg| {
                                assert_eq!(pkg.packet().len(), 20);
                                pkg.packet_mut()[0] = 9;
                                pkg.packet_mut()[19] = 201;
                            })
            .unwrap()
            .unwrap();
        let pkg = read_handle.try_recv().expect("Expected one packet to be sent");
        assert!(read_handle.try_recv().is_err());
        assert_eq!(pkg.len(), 20);
        assert_eq!(pkg[0], 9);
        assert_eq!(pkg[19], 201);
    }

    #[test]
    fn send_multiple_packets() {
        let (_, read_handle, mut tx, _) = create_net();
        // Check that sending multiple packets does the correct thing
        let mut closure_counter = 0;
        tx.build_and_send(3,
                            20,
                            &mut |mut pkg| {
                                pkg.packet_mut()[0] = closure_counter;
                                closure_counter += 1;
                            })
            .unwrap()
            .unwrap();
        for i in 0..3 {
            let pkg = read_handle.try_recv().expect("Expected a packet");
            assert_eq!(pkg[0], i);
        }
        assert!(read_handle.try_recv().is_err());
    }

    #[test]
    fn send_to() {
        let (_, read_handle, mut tx, _) = create_net();
        let mut buffer = vec![0; 20];
        buffer[1] = 34;
        buffer[18] = 76;
        let pkg = EthernetPacket::new(&buffer[..]).unwrap();

        tx.send_to(&pkg, None).unwrap().unwrap();
        let pkg = read_handle.try_recv().expect("Expected one packet to be sent");
        assert!(read_handle.try_recv().is_err());
        assert_eq!(pkg.len(), 20);
        assert_eq!(pkg[1], 34);
        assert_eq!(pkg[18], 76);
    }

    #[test]
    fn read_nothing() {
        let (inject_handle, _, _, mut rx) = create_net();
        let (control_tx, control_rx) = mpsc::channel();
        spawn(move || {
            let mut rx_iter = rx.iter();
            rx_iter.next().expect("Should not happen 1");
            control_tx.send(()).expect("Should not happen 2");
        });
        sleep(Duration::new(0, 1_000_000));
        match control_rx.try_recv() {
            Ok(_) => panic!("Nothing should have arrived"),
            Err(TryRecvError::Disconnected) => panic!("Thread should not have quit"),
            Err(TryRecvError::Empty) => (),
        }
    }

    #[test]
    fn read_one_pkg() {
        let (inject_handle, _, _, mut rx) = create_net();

        let buffer = vec![0; 20];
        inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();

        let mut rx_iter = rx.iter();
        let pkg = rx_iter.next().expect("Expected a packet");
        assert_eq!(pkg.packet().len(), 20);
    }

    #[test]
    fn read_multiple_pkgs() {
        let (inject_handle, _, _, mut rx) = create_net();

        for i in 0..3 {
            let buffer = vec![i; 20];
            inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();
        }

        let mut rx_iter = rx.iter();
        {
            let pkg1 = rx_iter.next().expect("Expected a packet");
            assert_eq!(pkg1.packet()[0], 0);
        }
        {
            let pkg2 = rx_iter.next().expect("Expected a packet");
            assert_eq!(pkg2.packet()[0], 1);
        }
        {
            let pkg3 = rx_iter.next().expect("Expected a packet");
            assert_eq!(pkg3.packet()[0], 2);
        }
    }

    fn create_net()
        -> (Sender<io::Result<Box<[u8]>>>,
            Receiver<Box<[u8]>>,
            Box<EthernetDataLinkSender>,
            Box<EthernetDataLinkReceiver>) {
        let interface = super::dummy_interface(56);
        let mut config = super::Config::default();
        let inject_handle = config.inject_handle().unwrap();
        let read_handle = config.read_handle().unwrap();

        let channel = super::channel(&interface, config);
        let (tx, rx) = match channel {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            _ => panic!("Not a valid channel returned"),
        };
        (inject_handle, read_handle, tx, rx)
    }
}
