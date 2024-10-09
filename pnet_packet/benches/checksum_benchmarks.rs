#![feature(test)]

mod checksum_benchmarks {
    extern crate test;
    use pnet_packet::util::checksum;
    use test::{black_box, Bencher};

    #[bench]
    fn bench_checksum_small(b: &mut Bencher) {
        let data = vec![99u8; 20];
        b.iter(|| checksum(black_box(&data), 5));
    }

    #[bench]
    fn bench_checksum_large(b: &mut Bencher) {
        let data = vec![123u8; 1024];
        b.iter(|| checksum(black_box(&data), 5));
    }
}
