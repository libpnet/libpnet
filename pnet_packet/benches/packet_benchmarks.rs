#![feature(test)]
extern crate test;
use test::{Bencher, black_box};

use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::ethernet::MutableEthernetPacket;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_base::MacAddr;
use pnet_packet::Packet;
use pnet_packet::ipv4::Ipv4Packet;

#[bench]
fn bench_packet_new_constructor(b: &mut Bencher) {
    let buffer = vec![0; 20];
    b.iter(|| EthernetPacket::new(black_box(&buffer)).unwrap());
}

#[bench]
fn bench_packet_get_source(b: &mut Bencher) {
    let buffer = vec![0; 20];
    let packet = EthernetPacket::new(&buffer).unwrap();
    b.iter(|| black_box(packet.get_source()));
}

#[bench]
fn bench_packet_set_source_black_box(b: &mut Bencher) {
    let mut buffer = vec![0; 20];
    let mut packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    let mac = MacAddr::new(1, 2, 3, 4, 5, 6);
    b.iter(|| packet.set_source(black_box(mac)));
}

#[bench]
fn bench_packet_mutable_to_immutable(b: &mut Bencher) {
    let mut buffer = vec![0; 20];
    let mut packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    b.iter(|| black_box(packet.to_immutable()));
}

#[bench]
fn bench_packet_immutable_to_immutable(b: &mut Bencher) {
    let mut buffer = vec![0; 20];
    let mut packet = EthernetPacket::new(&mut buffer).unwrap();
    b.iter(|| black_box(packet.to_immutable()));
}

#[bench]
fn bench_ipv4_parsing(b: &mut Bencher) {
    let data = hex::decode("000c291ce319ecf4bbd93e7d08004500002e1b6540008006cd76c0a8c887c0a8c8151a3707d0dd6abb2b1f5fd25150180402120f000068656c6c6f0a").unwrap();
    let ethernet = EthernetPacket::new(&data).unwrap();
    let payload = ethernet.payload().clone();
    b.iter(|| 
        Ipv4Packet::new(black_box(&payload))
    );

}
