// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Utilities for working with packets, eg. checksumming.

use crate::ip::IpNextHeaderProtocol;
use pnet_macros_support::types::u16be;

use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::u16;
use std::u8;

/// Convert a value to a byte array.
pub trait Octets {
    /// Output type - bytes array.
    type Output;

    /// Return a value as bytes (big-endian order).
    fn octets(&self) -> Self::Output;
}

impl Octets for u64 {
    type Output = [u8; 8];

    fn octets(&self) -> Self::Output {
        [
            (*self >> 56) as u8,
            (*self >> 48) as u8,
            (*self >> 40) as u8,
            (*self >> 32) as u8,
            (*self >> 24) as u8,
            (*self >> 16) as u8,
            (*self >> 8) as u8,
            *self as u8,
        ]
    }
}

impl Octets for u32 {
    type Output = [u8; 4];

    fn octets(&self) -> Self::Output {
        [
            (*self >> 24) as u8,
            (*self >> 16) as u8,
            (*self >> 8) as u8,
            *self as u8,
        ]
    }
}

impl Octets for u16 {
    type Output = [u8; 2];

    fn octets(&self) -> Self::Output {
        [(*self >> 8) as u8, *self as u8]
    }
}

impl Octets for u8 {
    type Output = [u8; 1];

    fn octets(&self) -> Self::Output {
        [*self]
    }
}

/// Calculates a checksum. Used by ipv4 and icmp. The two bytes starting at `skipword * 2` will be
/// ignored. Supposed to be the checksum field, which is regarded as zero during calculation.
pub fn checksum(data: &[u8], skipword: usize) -> u16be {
    if data.len() == 0 {
        return 0;
    }
    let sum = sum_be_words(data, skipword);
    finalize_checksum(sum)
}

fn finalize_checksum(mut sum: u32) -> u16be {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

/// Calculate the checksum for a packet built on IPv4. Used by UDP and TCP.
pub fn ipv4_checksum(
    data: &[u8],
    skipword: usize,
    extra_data: &[u8],
    source: &Ipv4Addr,
    destination: &Ipv4Addr,
    next_level_protocol: IpNextHeaderProtocol,
) -> u16be {
    let mut sum = 0u32;

    // Checksum pseudo-header
    sum += ipv4_word_sum(source);
    sum += ipv4_word_sum(destination);

    let IpNextHeaderProtocol(next_level_protocol) = next_level_protocol;
    sum += next_level_protocol as u32;

    let len = data.len() + extra_data.len();
    sum += len as u32;

    // Checksum packet header and data
    sum += sum_be_words(data, skipword);
    sum += sum_be_words(extra_data, extra_data.len() / 2);

    finalize_checksum(sum)
}

fn ipv4_word_sum(ip: &Ipv4Addr) -> u32 {
    let octets = ip.octets();
    ((octets[0] as u32) << 8 | octets[1] as u32) + ((octets[2] as u32) << 8 | octets[3] as u32)
}

/// Calculate the checksum for a packet built on IPv6.
pub fn ipv6_checksum(
    data: &[u8],
    skipword: usize,
    extra_data: &[u8],
    source: &Ipv6Addr,
    destination: &Ipv6Addr,
    next_level_protocol: IpNextHeaderProtocol,
) -> u16be {
    let mut sum = 0u32;

    // Checksum pseudo-header
    sum += ipv6_word_sum(source);
    sum += ipv6_word_sum(destination);

    let IpNextHeaderProtocol(next_level_protocol) = next_level_protocol;
    sum += next_level_protocol as u32;

    let len = data.len() + extra_data.len();
    sum += len as u32;

    // Checksum packet header and data
    sum += sum_be_words(data, skipword);
    sum += sum_be_words(extra_data, extra_data.len() / 2);

    finalize_checksum(sum)
}

fn ipv6_word_sum(ip: &Ipv6Addr) -> u32 {
    ip.segments().iter().map(|x| *x as u32).sum()
}

/// Sum all words (16 bit chunks) in the given data. The word at word offset
/// `skipword` will be skipped. Each word is treated as big endian.
fn sum_be_words(data: &[u8], skipword: usize) -> u32 {
    if data.len() == 0 {
        return 0;
    }
    let len = data.len();
    let mut cur_data = &data[..];
    let mut sum = 0u32;
    let mut i = 0;
    while cur_data.len() >= 2 {
        if i != skipword {
            // It's safe to unwrap because we verified there are at least 2 bytes
            sum += u16::from_be_bytes(cur_data[0..2].try_into().unwrap()) as u32;
        }
        cur_data = &cur_data[2..];
        i += 1;
    }

    // If the length is odd, make sure to checksum the final byte
    if i != skipword && len & 1 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    sum
}

#[cfg(test)]
mod tests {
    use super::sum_be_words;
    use std::slice;

    #[test]
    fn sum_be_words_different_skipwords() {
        let data = (0..11).collect::<Vec<u8>>();
        assert_eq!(7190, sum_be_words(&data, 1));
        assert_eq!(6676, sum_be_words(&data, 2));
        // Assert having the skipword outside the range gives correct and equal
        // results
        assert_eq!(7705, sum_be_words(&data, 99));
        assert_eq!(7705, sum_be_words(&data, 101));
    }

    #[test]
    fn sum_be_words_small_sizes() {
        let data_zero = vec![0; 0];
        assert_eq!(0, sum_be_words(&data_zero, 0));
        assert_eq!(0, sum_be_words(&data_zero, 10));
        let data_one = vec![1; 1];
        assert_eq!(0, sum_be_words(&data_zero, 0));
        assert_eq!(256, sum_be_words(&data_one, 1));
        let data_two = vec![1; 2];
        assert_eq!(0, sum_be_words(&data_two, 0));
        assert_eq!(257, sum_be_words(&data_two, 1));
        let data_three = vec![4; 3];
        assert_eq!(1024, sum_be_words(&data_three, 0));
        assert_eq!(1028, sum_be_words(&data_three, 1));
        assert_eq!(2052, sum_be_words(&data_three, 2));
        assert_eq!(2052, sum_be_words(&data_three, 3));
    }

    #[test]
    fn sum_be_words_misaligned_ptr() {
        let mut data = vec![0; 13];
        let ptr = match data.as_ptr() as usize % 2 {
            0 => unsafe { data.as_mut_ptr().offset(1) },
            _ => data.as_mut_ptr(),
        };
        unsafe {
            let slice_data = slice::from_raw_parts_mut(ptr, 12);
            for i in 0..11 {
                slice_data[i] = i as u8;
            }
            assert_eq!(7190, sum_be_words(&slice_data, 1));
            assert_eq!(6676, sum_be_words(&slice_data, 2));
            // Assert having the skipword outside the range gives correct and equal
            // results
            assert_eq!(7705, sum_be_words(&slice_data, 99));
            assert_eq!(7705, sum_be_words(&slice_data, 101));
        }
    }
}

#[cfg(all(test, feature = "benchmark"))]
mod checksum_benchmarks {
    use super::checksum;
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
