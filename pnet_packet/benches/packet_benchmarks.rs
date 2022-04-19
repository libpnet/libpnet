//Using criterion so that we dont need to use the test framework which requires nightly toolchain
use criterion::{criterion_group, criterion_main, Criterion, black_box};

use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::ethernet::MutableEthernetPacket;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_base::MacAddr;
use pnet_packet::Packet;
use pnet_packet::ipv4::Ipv4Packet;


fn bench_packet_new_constructor(c: &mut Criterion) {
    let buffer = vec![0; 20];
    c.bench_function("EthernetPacket New Packet", |b| {
        b.iter(|| 
            EthernetPacket::new(black_box(&buffer)).unwrap()
        );
    });
}

fn bench_packet_get_source(c: &mut Criterion) {
    let buffer = vec![0; 20];
    let packet = EthernetPacket::new(&buffer).unwrap();
    c.bench_function("EthernetPacket Get Source", |b| {
        b.iter(|| 
            black_box(packet.get_source())
        );
    });
}

fn bench_packet_set_source_black_box(c: &mut Criterion) {
    let mut buffer = vec![0; 20];
    let mut packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    let mac = MacAddr::new(1, 2, 3, 4, 5, 6);
    c.bench_function("EthernetPacket Set Source", |b| {
        b.iter(|| 
            packet.set_source(black_box(mac))
        );
    });
}

fn bench_packet_mutable_to_immutable(c: &mut Criterion) {
    let mut buffer = vec![0; 20];
    let mut packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    c.bench_function("Mutable to Immutable", |b| {
        b.iter(|| 
            black_box(packet.to_immutable())
        );
    });
}

fn bench_packet_immutable_to_immutable(c: &mut Criterion) {
    let mut buffer = vec![0; 20];
    let mut packet = EthernetPacket::new(&mut buffer).unwrap();
    c.bench_function("Immutable to Immutable", |b| {
        b.iter(|| 
            black_box(packet.to_immutable())
        );
    });
}

fn bench_ipv4_parsing(c: &mut Criterion) {
    let data = hex::decode("000c291ce319ecf4bbd93e7d08004500002e1b6540008006cd76c0a8c887c0a8c8151a3707d0dd6abb2b1f5fd25150180402120f000068656c6c6f0a").unwrap();
    let ethernet = EthernetPacket::new(&data).unwrap();
    let payload = ethernet.payload().clone();
    c.bench_function("IPV4 Parsing", |b| {
        b.iter(|| 
            Ipv4Packet::new(black_box(&payload))
        );
    });
}

criterion_group!(benches, bench_packet_new_constructor, bench_packet_get_source, bench_packet_set_source_black_box, bench_packet_mutable_to_immutable, bench_packet_immutable_to_immutable, bench_ipv4_parsing);

criterion_main!(benches);