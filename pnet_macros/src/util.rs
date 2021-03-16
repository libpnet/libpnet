// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
// Copyright (c) 2021 Pierre Chifflier <chifflier@wzdftpd.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Utility functions for bit manipulation operations

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Big,
    Little,
    Host,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetOperation {
    mask: u8,
    shiftl: u8,
    shiftr: u8,
}

impl fmt::Display for GetOperation {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let should_mask = self.mask != 0xFF;
        let shift = (self.shiftr as i16) - (self.shiftl as i16);

        let mask_str = if should_mask {
            format!("({{}} & 0x{})", radix16_u8(self.mask))
        } else {
            "{}".to_owned()
        };

        if shift == 0 {
            write!(fmt, "{}", mask_str)
        } else if shift < 0 {
            write!(fmt, "{} << {}", mask_str, shift.abs())
        } else {
            write!(fmt, "{} >> {}", mask_str, shift.abs())
        }
    }
}

#[test]
fn test_display_get_operation() {
    type Op = GetOperation;

    assert_eq!(
        Op {
            mask: 0b00001111,
            shiftl: 2,
            shiftr: 0,
        }
        .to_string(),
        "({} & 0xf) << 2"
    );
    assert_eq!(
        Op {
            mask: 0b00001111,
            shiftl: 2,
            shiftr: 2,
        }
        .to_string(),
        "({} & 0xf)"
    );
    assert_eq!(
        Op {
            mask: 0b00001111,
            shiftl: 0,
            shiftr: 2,
        }
        .to_string(),
        "({} & 0xf) >> 2"
    );
    assert_eq!(
        Op {
            mask: 0b11111111,
            shiftl: 0,
            shiftr: 2,
        }
        .to_string(),
        "{} >> 2"
    );
    assert_eq!(
        Op {
            mask: 0b11111111,
            shiftl: 3,
            shiftr: 1,
        }
        .to_string(),
        "{} << 2"
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetOperation {
    /// Bits to save from old byte
    save_mask: u8,
    /// Bits to mask out of value we're setting
    value_mask: u64,
    /// Number of places to left shift the value we're setting
    shiftl: u8,
    /// Number of places to right shift the value we're setting
    shiftr: u8,
}

macro_rules! radix_fn {
    ($name:ident, $ty:ty) => {
        fn $name(mut val: $ty) -> String {
            let mut ret = String::new();
            let vals = "0123456789abcdef".as_bytes();
            while val > 0 {
                let remainder = val % 16;
                val /= 16;
                ret = format!("{}{}", vals[remainder as usize] as char, ret);
            }

            ret
        }

        mod $name {
            #[test]
            fn test() {
                assert_eq!(super::$name(0xab), "ab".to_owned());
                assert_eq!(super::$name(0x1c), "1c".to_owned());
            }
        }
    };
}

radix_fn!(radix16_u8, u8);
radix_fn!(radix16_u64, u64);

impl fmt::Display for SetOperation {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let should_mask = self.value_mask != 0xFF;
        let should_save = self.save_mask != 0x00;
        let shift = (self.shiftr as i16) - (self.shiftl as i16);

        let save_str = if should_save {
            format!("({{packet}} & 0x{})", radix16_u8(self.save_mask))
        } else {
            "".to_owned()
        };

        let mask_str = if should_mask {
            format!("({{val}} & 0x{})", radix16_u64(self.value_mask))
        } else {
            "{val}".to_owned()
        };

        let shift_str = if shift == 0 {
            format!("{}", mask_str)
        } else if shift < 0 {
            format!("{} << {}", mask_str, shift.abs())
        } else {
            format!("{} >> {}", mask_str, shift.abs())
        };

        if should_save {
            write!(
                fmt,
                "{{packet}} = ({} | ({}) as u8) as u8",
                save_str, shift_str
            )
        } else {
            write!(fmt, "{{packet}} = ({}) as u8", shift_str)
        }
    }
}

#[test]
fn test_display_set_operation() {
    type Sop = SetOperation;

    assert_eq!(
        Sop {
            save_mask: 0b00000011,
            value_mask: 0b00001111,
            shiftl: 2,
            shiftr: 0,
        }
        .to_string(),
        "{packet} = (({packet} & 0x3) | (({val} & 0xf) << 2) as u8) as u8"
    );
    assert_eq!(
        Sop {
            save_mask: 0b11000000,
            value_mask: 0b00001111,
            shiftl: 2,
            shiftr: 2,
        }
        .to_string(),
        "{packet} = (({packet} & 0xc0) | (({val} & 0xf)) as u8) as u8"
    );
    assert_eq!(
        Sop {
            save_mask: 0b00011100,
            value_mask: 0b00001111,
            shiftl: 0,
            shiftr: 2,
        }
        .to_string(),
        "{packet} = (({packet} & 0x1c) | (({val} & 0xf) >> 2) as u8) as u8"
    );
    assert_eq!(
        Sop {
            save_mask: 0b00000000,
            value_mask: 0b11111111,
            shiftl: 0,
            shiftr: 2,
        }
        .to_string(),
        "{packet} = ({val} >> 2) as u8"
    );
    assert_eq!(
        Sop {
            save_mask: 0b00000011,
            value_mask: 0b11111111,
            shiftl: 3,
            shiftr: 1,
        }
        .to_string(),
        "{packet} = (({packet} & 0x3) | ({val} << 2) as u8) as u8"
    );
}

/// Gets a mask to get bits_remaining bits from offset bits into a byte
/// If bits_remaining is > 8, it will be truncated as necessary
fn get_mask(offset: usize, bits_remaining: usize) -> (usize, u8) {
    fn bits_remaining_in_byte(offset: usize, bits_remaining: usize) -> usize {
        fn round_down(max_val: usize, val: usize) -> usize {
            if val > max_val {
                max_val
            } else {
                val
            }
        }
        if (bits_remaining / 8) >= 1 {
            8 - offset
        } else {
            round_down(8 - offset, bits_remaining)
        }
    }
    assert!(offset <= 7);
    let mut num_bits_to_mask = bits_remaining_in_byte(offset, bits_remaining);
    assert!(num_bits_to_mask <= 8 - offset);
    let mut mask = 0;
    while num_bits_to_mask > 0 {
        mask = mask | (0x80 >> (offset + num_bits_to_mask - 1));
        num_bits_to_mask -= 1;
    }

    (bits_remaining_in_byte(offset, bits_remaining), mask)
}

#[test]
fn test_get_mask() {
    assert_eq!(get_mask(0, 1), (1, 0b10000000));
    assert_eq!(get_mask(0, 2), (2, 0b11000000));
    assert_eq!(get_mask(0, 3), (3, 0b11100000));
    assert_eq!(get_mask(0, 4), (4, 0b11110000));
    assert_eq!(get_mask(0, 5), (5, 0b11111000));
    assert_eq!(get_mask(0, 6), (6, 0b11111100));
    assert_eq!(get_mask(0, 7), (7, 0b11111110));
    assert_eq!(get_mask(0, 8), (8, 0b11111111));
    assert_eq!(get_mask(0, 9), (8, 0b11111111));
    assert_eq!(get_mask(0, 100), (8, 0b11111111));

    assert_eq!(get_mask(1, 1), (1, 0b01000000));
    assert_eq!(get_mask(1, 2), (2, 0b01100000));
    assert_eq!(get_mask(1, 3), (3, 0b01110000));
    assert_eq!(get_mask(1, 4), (4, 0b01111000));
    assert_eq!(get_mask(1, 5), (5, 0b01111100));
    assert_eq!(get_mask(1, 6), (6, 0b01111110));
    assert_eq!(get_mask(1, 7), (7, 0b01111111));
    assert_eq!(get_mask(1, 8), (7, 0b01111111));
    assert_eq!(get_mask(1, 9), (7, 0b01111111));
    assert_eq!(get_mask(1, 100), (7, 0b01111111));

    assert_eq!(get_mask(5, 1), (1, 0b00000100));
    assert_eq!(get_mask(5, 2), (2, 0b00000110));
    assert_eq!(get_mask(5, 3), (3, 0b00000111));
    assert_eq!(get_mask(5, 4), (3, 0b00000111));
    assert_eq!(get_mask(5, 5), (3, 0b00000111));
    assert_eq!(get_mask(5, 6), (3, 0b00000111));
    assert_eq!(get_mask(5, 7), (3, 0b00000111));
    assert_eq!(get_mask(5, 8), (3, 0b00000111));
    assert_eq!(get_mask(5, 100), (3, 0b00000111));
}

fn get_shiftl(offset: usize, size: usize, byte_number: usize, num_bytes: usize) -> u8 {
    if num_bytes == 1 || byte_number + 1 == num_bytes {
        0
    } else {
        let base_shift = 8 - ((num_bytes * 8) - offset - size);
        let bytes_to_shift = num_bytes - byte_number - 2;

        let ret = base_shift + (8 * bytes_to_shift);

        // (ret % 8) as u8
        ret as u8
    }
}

#[test]
fn test_get_shiftl() {
    assert_eq!(get_shiftl(0, 8, 0, 1), 0);
    assert_eq!(get_shiftl(0, 9, 0, 2), 1);
    assert_eq!(get_shiftl(0, 9, 1, 2), 0);
    assert_eq!(get_shiftl(0, 10, 0, 2), 2);
    assert_eq!(get_shiftl(0, 10, 1, 2), 0);
    assert_eq!(get_shiftl(0, 11, 0, 2), 3);
    assert_eq!(get_shiftl(0, 11, 1, 2), 0);

    assert_eq!(get_shiftl(1, 7, 0, 1), 0);
    assert_eq!(get_shiftl(1, 8, 0, 2), 1);
    assert_eq!(get_shiftl(1, 9, 0, 2), 2);
    assert_eq!(get_shiftl(1, 9, 1, 2), 0);
    assert_eq!(get_shiftl(1, 10, 0, 2), 3);
    assert_eq!(get_shiftl(1, 10, 1, 2), 0);
    assert_eq!(get_shiftl(1, 11, 0, 2), 4);
    assert_eq!(get_shiftl(1, 11, 1, 2), 0);

    assert_eq!(get_shiftl(0, 35, 0, 5), 27);
    assert_eq!(get_shiftl(0, 35, 1, 5), 19);
    assert_eq!(get_shiftl(0, 35, 2, 5), 11);
    assert_eq!(get_shiftl(0, 35, 3, 5), 3);
    assert_eq!(get_shiftl(0, 35, 4, 5), 0);
}

fn get_shiftr(offset: usize, size: usize, byte_number: usize, num_bytes: usize) -> u8 {
    if byte_number + 1 == num_bytes {
        ((num_bytes * 8) - offset - size) as u8
    } else {
        0
    }
}

#[test]
fn test_get_shiftr() {
    assert_eq!(get_shiftr(0, 1, 0, 1), 7);
    assert_eq!(get_shiftr(0, 2, 0, 1), 6);
    assert_eq!(get_shiftr(0, 3, 0, 1), 5);
    assert_eq!(get_shiftr(0, 4, 0, 1), 4);
    assert_eq!(get_shiftr(0, 5, 0, 1), 3);
    assert_eq!(get_shiftr(0, 6, 0, 1), 2);
    assert_eq!(get_shiftr(0, 7, 0, 1), 1);
    assert_eq!(get_shiftr(0, 8, 0, 1), 0);
    assert_eq!(get_shiftr(0, 9, 0, 2), 0);
    assert_eq!(get_shiftr(0, 9, 1, 2), 7);

    assert_eq!(get_shiftr(1, 7, 0, 1), 0);
    assert_eq!(get_shiftr(1, 8, 0, 2), 0);
    assert_eq!(get_shiftr(1, 8, 1, 2), 7);
    assert_eq!(get_shiftr(1, 9, 0, 2), 0);
    assert_eq!(get_shiftr(1, 9, 1, 2), 6);
    assert_eq!(get_shiftr(1, 10, 0, 2), 0);
    assert_eq!(get_shiftr(1, 10, 1, 2), 5);
    assert_eq!(get_shiftr(1, 11, 0, 2), 0);
    assert_eq!(get_shiftr(1, 11, 1, 2), 4);

    assert_eq!(get_shiftr(0, 35, 0, 5), 0);
    assert_eq!(get_shiftr(0, 35, 1, 5), 0);
    assert_eq!(get_shiftr(0, 35, 2, 5), 0);
    assert_eq!(get_shiftr(0, 35, 3, 5), 0);
    assert_eq!(get_shiftr(0, 35, 4, 5), 5);
}

/// Given an offset (number of bits into a chunk of memory), retrieve a list of operations to get
/// size bits.
///
/// Assumes big endian, and that each byte will be masked, then cast to the next power of two
/// greater than or equal to size bits before shifting. offset should be in the range [0, 7]
pub fn operations(offset: usize, size: usize) -> Option<Vec<GetOperation>> {
    if offset > 7 || size == 0 || size > 64 {
        return None;
    }

    let num_full_bytes = size / 8;
    let num_bytes = if offset > 0 || size % 8 != 0 {
        num_full_bytes + 1
    } else {
        num_full_bytes
    };

    let mut current_offset = offset;
    let mut num_bits_remaining = size;
    let mut ops = Vec::with_capacity(num_bytes);
    for i in 0..num_bytes {
        let (consumed, mask) = get_mask(current_offset, num_bits_remaining);
        ops.push(GetOperation {
            mask: mask,
            shiftl: get_shiftl(offset, size, i, num_bytes),
            shiftr: get_shiftr(offset, size, i, num_bytes),
        });
        current_offset = 0;
        if num_bits_remaining >= consumed {
            num_bits_remaining -= consumed;
        }
    }

    Some(ops)
}

#[test]
fn operations_test() {
    type Op = GetOperation;
    assert_eq!(
        operations(0, 1).unwrap(),
        vec![Op {
            mask: 0b10000000,
            shiftl: 0,
            shiftr: 7,
        }]
    );
    assert_eq!(
        operations(0, 2).unwrap(),
        vec![Op {
            mask: 0b11000000,
            shiftl: 0,
            shiftr: 6,
        }]
    );
    assert_eq!(
        operations(0, 3).unwrap(),
        vec![Op {
            mask: 0b11100000,
            shiftl: 0,
            shiftr: 5,
        }]
    );
    assert_eq!(
        operations(0, 4).unwrap(),
        vec![Op {
            mask: 0b11110000,
            shiftl: 0,
            shiftr: 4,
        }]
    );
    assert_eq!(
        operations(0, 5).unwrap(),
        vec![Op {
            mask: 0b11111000,
            shiftl: 0,
            shiftr: 3,
        }]
    );
    assert_eq!(
        operations(0, 6).unwrap(),
        vec![Op {
            mask: 0b11111100,
            shiftl: 0,
            shiftr: 2,
        }]
    );
    assert_eq!(
        operations(0, 7).unwrap(),
        vec![Op {
            mask: 0b11111110,
            shiftl: 0,
            shiftr: 1,
        }]
    );
    assert_eq!(
        operations(0, 8).unwrap(),
        vec![Op {
            mask: 0b11111111,
            shiftl: 0,
            shiftr: 0,
        }]
    );
    assert_eq!(
        operations(0, 9).unwrap(),
        vec![
            Op {
                mask: 0b11111111,
                shiftl: 1,
                shiftr: 0,
            },
            Op {
                mask: 0b10000000,
                shiftl: 0,
                shiftr: 7,
            }
        ]
    );
    assert_eq!(
        operations(0, 10).unwrap(),
        vec![
            Op {
                mask: 0b11111111,
                shiftl: 2,
                shiftr: 0,
            },
            Op {
                mask: 0b11000000,
                shiftl: 0,
                shiftr: 6,
            }
        ]
    );

    assert_eq!(
        operations(1, 1).unwrap(),
        vec![Op {
            mask: 0b01000000,
            shiftl: 0,
            shiftr: 6,
        }]
    );
    assert_eq!(
        operations(1, 2).unwrap(),
        vec![Op {
            mask: 0b01100000,
            shiftl: 0,
            shiftr: 5,
        }]
    );
    assert_eq!(
        operations(1, 3).unwrap(),
        vec![Op {
            mask: 0b01110000,
            shiftl: 0,
            shiftr: 4,
        }]
    );
    assert_eq!(
        operations(1, 4).unwrap(),
        vec![Op {
            mask: 0b01111000,
            shiftl: 0,
            shiftr: 3,
        }]
    );
    assert_eq!(
        operations(1, 5).unwrap(),
        vec![Op {
            mask: 0b01111100,
            shiftl: 0,
            shiftr: 2,
        }]
    );
    assert_eq!(
        operations(1, 6).unwrap(),
        vec![Op {
            mask: 0b01111110,
            shiftl: 0,
            shiftr: 1,
        }]
    );
    assert_eq!(
        operations(1, 7).unwrap(),
        vec![Op {
            mask: 0b01111111,
            shiftl: 0,
            shiftr: 0,
        }]
    );
    assert_eq!(
        operations(1, 8).unwrap(),
        vec![
            Op {
                mask: 0b01111111,
                shiftl: 1,
                shiftr: 0,
            },
            Op {
                mask: 0b10000000,
                shiftl: 0,
                shiftr: 7,
            }
        ]
    );
    assert_eq!(
        operations(1, 9).unwrap(),
        vec![
            Op {
                mask: 0b01111111,
                shiftl: 2,
                shiftr: 0,
            },
            Op {
                mask: 0b11000000,
                shiftl: 0,
                shiftr: 6,
            }
        ]
    );

    assert_eq!(operations(8, 1), None);
    assert_eq!(operations(3, 0), None);
    assert_eq!(operations(3, 65), None);

    assert_eq!(
        operations(3, 33).unwrap(),
        vec![
            Op {
                mask: 0b00011111,
                shiftl: 28,
                shiftr: 0,
            },
            Op {
                mask: 0b11111111,
                shiftl: 20,
                shiftr: 0,
            },
            Op {
                mask: 0b11111111,
                shiftl: 12,
                shiftr: 0,
            },
            Op {
                mask: 0b11111111,
                shiftl: 4,
                shiftr: 0,
            },
            Op {
                mask: 0b11110000,
                shiftl: 0,
                shiftr: 4,
            }
        ]
    );
}

/// Mask `bits` bits of a byte. eg. mask_high_bits(2) == 0b00000011
fn mask_high_bits(mut bits: u64) -> u64 {
    let mut mask = 0;
    while bits > 0 {
        mask = mask | (1 << (bits - 1));
        bits -= 1;
    }

    mask
}

/// Converts a set of operations which would get a field, to a set of operations which would set
/// the field
///
/// In the form of (bits to get, bits to set)
pub fn to_mutator(ops: &[GetOperation]) -> Vec<SetOperation> {
    fn num_bits_set(n: u8) -> u64 {
        let mut count = 0;
        for i in 0..8 {
            if n & (1 << i) > 0 {
                count += 1;
            }
        }

        count
    }

    let mut sops = Vec::with_capacity(ops.len());
    for op in ops {
        sops.push(SetOperation {
            save_mask: !op.mask,
            value_mask: mask_high_bits(num_bits_set(op.mask)) << op.shiftl,
            shiftl: op.shiftr,
            shiftr: op.shiftl,
        });
    }

    sops
}

#[test]
fn test_to_mutator() {
    type Op = GetOperation;
    type Sop = SetOperation;

    assert_eq!(
        to_mutator(&[Op {
            mask: 0b10000000,
            shiftl: 0,
            shiftr: 7,
        }]),
        vec![Sop {
            save_mask: 0b01111111,
            value_mask: 0b00000001,
            shiftl: 7,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b11000000,
            shiftl: 0,
            shiftr: 6,
        }]),
        vec![Sop {
            save_mask: 0b00111111,
            value_mask: 0b00000011,
            shiftl: 6,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b11100000,
            shiftl: 0,
            shiftr: 5,
        }]),
        vec![Sop {
            save_mask: 0b00011111,
            value_mask: 0b00000111,
            shiftl: 5,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b11110000,
            shiftl: 0,
            shiftr: 4,
        }]),
        vec![Sop {
            save_mask: 0b00001111,
            value_mask: 0b00001111,
            shiftl: 4,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b11111000,
            shiftl: 0,
            shiftr: 3,
        }]),
        vec![Sop {
            save_mask: 0b00000111,
            value_mask: 0b00011111,
            shiftl: 3,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b11111100,
            shiftl: 0,
            shiftr: 2,
        }]),
        vec![Sop {
            save_mask: 0b00000011,
            value_mask: 0b00111111,
            shiftl: 2,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b11111110,
            shiftl: 0,
            shiftr: 1,
        }]),
        vec![Sop {
            save_mask: 0b00000001,
            value_mask: 0b01111111,
            shiftl: 1,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b11111111,
            shiftl: 0,
            shiftr: 0,
        }]),
        vec![Sop {
            save_mask: 0b00000000,
            value_mask: 0b11111111,
            shiftl: 0,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[
            Op {
                mask: 0b11111111,
                shiftl: 1,
                shiftr: 0,
            },
            Op {
                mask: 0b10000000,
                shiftl: 0,
                shiftr: 7,
            }
        ]),
        vec![
            Sop {
                save_mask: 0b00000000,
                value_mask: 0b111111110,
                shiftl: 0,
                shiftr: 1,
            },
            Sop {
                save_mask: 0b01111111,
                value_mask: 0b00000001,
                shiftl: 7,
                shiftr: 0,
            }
        ]
    );

    assert_eq!(
        to_mutator(&[
            Op {
                mask: 0b11111111,
                shiftl: 2,
                shiftr: 0,
            },
            Op {
                mask: 0b11000000,
                shiftl: 0,
                shiftr: 6,
            }
        ]),
        vec![
            Sop {
                save_mask: 0b00000000,
                value_mask: 0b1111111100,
                shiftl: 0,
                shiftr: 2,
            },
            Sop {
                save_mask: 0b00111111,
                value_mask: 0b00000011,
                shiftl: 6,
                shiftr: 0,
            }
        ]
    );

    assert_eq!(
        to_mutator(&[Op {
            mask: 0b01000000,
            shiftl: 0,
            shiftr: 6,
        }]),
        vec![Sop {
            save_mask: 0b10111111,
            value_mask: 0b00000001,
            shiftl: 6,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b01100000,
            shiftl: 0,
            shiftr: 5,
        }]),
        vec![Sop {
            save_mask: 0b10011111,
            value_mask: 0b00000011,
            shiftl: 5,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b01110000,
            shiftl: 0,
            shiftr: 4,
        }]),
        vec![Sop {
            save_mask: 0b10001111,
            value_mask: 0b00000111,
            shiftl: 4,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b01111000,
            shiftl: 0,
            shiftr: 3,
        }]),
        vec![Sop {
            save_mask: 0b10000111,
            value_mask: 0b00001111,
            shiftl: 3,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b01111100,
            shiftl: 0,
            shiftr: 2,
        }]),
        vec![Sop {
            save_mask: 0b10000011,
            value_mask: 0b00011111,
            shiftl: 2,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b01111110,
            shiftl: 0,
            shiftr: 1,
        }]),
        vec![Sop {
            save_mask: 0b10000001,
            value_mask: 0b00111111,
            shiftl: 1,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[Op {
            mask: 0b01111111,
            shiftl: 0,
            shiftr: 0,
        }]),
        vec![Sop {
            save_mask: 0b10000000,
            value_mask: 0b01111111,
            shiftl: 0,
            shiftr: 0,
        }]
    );
    assert_eq!(
        to_mutator(&[
            Op {
                mask: 0b01111111,
                shiftl: 1,
                shiftr: 0,
            },
            Op {
                mask: 0b10000000,
                shiftl: 0,
                shiftr: 7,
            }
        ]),
        vec![
            Sop {
                save_mask: 0b10000000,
                value_mask: 0b11111110,
                shiftl: 0,
                shiftr: 1,
            },
            Sop {
                save_mask: 0b01111111,
                value_mask: 0b00000001,
                shiftl: 7,
                shiftr: 0,
            }
        ]
    );
    assert_eq!(
        to_mutator(&[
            Op {
                mask: 0b01111111,
                shiftl: 2,
                shiftr: 0,
            },
            Op {
                mask: 0b11000000,
                shiftl: 0,
                shiftr: 6,
            }
        ]),
        vec![
            Sop {
                save_mask: 0b10000000,
                value_mask: 0b0111111100,
                shiftl: 0,
                shiftr: 2,
            },
            Sop {
                save_mask: 0b00111111,
                value_mask: 0b00000011,
                shiftl: 6,
                shiftr: 0,
            }
        ]
    );

    assert_eq!(
        to_mutator(&[
            Op {
                mask: 0b00011111,
                shiftl: 28,
                shiftr: 0,
            },
            Op {
                mask: 0b11111111,
                shiftl: 20,
                shiftr: 0,
            },
            Op {
                mask: 0b11111111,
                shiftl: 12,
                shiftr: 0,
            },
            Op {
                mask: 0b11111111,
                shiftl: 4,
                shiftr: 0,
            },
            Op {
                mask: 0b11110000,
                shiftl: 0,
                shiftr: 4,
            }
        ]),
        vec![
            Sop {
                save_mask: 0b11100000,
                value_mask: 0x1F0000000,
                shiftl: 0,
                shiftr: 28,
            },
            Sop {
                save_mask: 0b00000000,
                value_mask: 0x00FF00000,
                shiftl: 0,
                shiftr: 20,
            },
            Sop {
                save_mask: 0b00000000,
                value_mask: 0x0000FF000,
                shiftl: 0,
                shiftr: 12,
            },
            Sop {
                save_mask: 0b00000000,
                value_mask: 0x000000FF0,
                shiftl: 0,
                shiftr: 4,
            },
            Sop {
                save_mask: 0b00001111,
                value_mask: 0x00000000F,
                shiftl: 4,
                shiftr: 0,
            }
        ]
    );
}

/// Takes a set of operations to get a field in big endian, and converts them to get the field in
/// little endian.
pub fn to_little_endian(_ops: Vec<GetOperation>) -> Vec<GetOperation> {
    let mut ops = _ops.clone();
    for (op, be_op) in ops.iter_mut().zip(_ops.iter().rev()) {
        op.shiftl = be_op.shiftl;
    }
    ops
}
