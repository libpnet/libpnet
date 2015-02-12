// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//#![warn(missing_docs)]

#![feature(core, plugin_registrar, rustc_private)]

extern crate syntax;
extern crate rustc;

use syntax::ast;
use syntax::codemap::{Span, Spanned};
use syntax::owned_slice::OwnedSlice;
use syntax::parse::token;
use syntax::ext::base::{ExtCtxt, Decorator};
use syntax::ext::build::AstBuilder;
use syntax::ext::quote::rt::ExtParseUtils;
use syntax::ptr::P;

use rustc::plugin::Registry;

enum Endianness {
    Big,
    Little
}

#[derive(Debug, PartialEq, Eq)]
struct Operation {
    mask: u8,
    shiftl: u8,
    shiftr: u8,
}

fn mask_high_bits(mut bits: u8) -> u8 {
    let mut mask = 0;
    while bits > 0 {
        mask = mask | (1 << bits);
        bits -= 1;
    }

    mask
}

/// Gets a mask to get bits_remaining bits from offset bits into a byte
/// If bits_remaining is > 8, it will be truncated as necessary
fn get_mask(offset: usize, bits_remaining: usize) -> (usize, u8) {
    println!("get_mask(offset={}, bits_remaining={})", offset, bits_remaining);
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
    println!("num_bits_to_mask: {}", num_bits_to_mask);
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
    //println!("get_shiftl(offset={}, size={}, byte_number={}, num_bytes={})", offset, size, byte_number, num_bytes);
    if num_bytes == 1 || byte_number + 1 == num_bytes {
        0
    } else {
        let base_shift = 8 - ((num_bytes * 8) - offset - size);
        let bytes_to_shift = num_bytes - byte_number - 2;

        //println!("base_shift: {}", base_shift);
        //println!("bytes_to_shift: {}", bytes_to_shift);

        (base_shift + (8 * bytes_to_shift)) as u8
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

/// Given an offset (number of bits into a chunk of memory), retreive a list of operations to get
/// size bits.
///
/// Assumes big endian, and that each byte will be masked, then cast to the next power of two
/// greater than or equal to size bits before shifting. offset should be in the range [0, 7]
fn operations(offset: usize, size: usize) -> Option<Vec<Operation>> {
    if offset > 7 || size == 0 || size > 64 {
        return None;
    }
    //let num_bits = size - offset;
    let num_full_bytes = size / 8;
    let num_bytes = if offset > 0 || size % 8 != 0{
                        num_full_bytes + 1
                    } else {
                        num_full_bytes
                    };
/*    let num_bytes = if size % 8 == 0 {
                        num_full_bytes
                    } else {
                        num_full_bytes + 1
                    };*/
    let mut current_offset = offset;
    let mut num_bits_remaining = size;
    let mut ops = Vec::with_capacity(num_bytes);
    for i in range(0, num_bytes) {
        //let num_bits = num_bits_remaining / 8;
        let (consumed, mask) = get_mask(current_offset, num_bits_remaining);
        println!("num_bits_remaining: {}", num_bits_remaining);
        println!("consumed: {}", consumed);
        ops.push(Operation {
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
    type Op = Operation;
    assert_eq!(operations(0, 1).unwrap(), vec!(Op { mask: 0b10000000, shiftl: 0, shiftr: 7 }));
    assert_eq!(operations(0, 2).unwrap(), vec!(Op { mask: 0b11000000, shiftl: 0, shiftr: 6 }));
    assert_eq!(operations(0, 3).unwrap(), vec!(Op { mask: 0b11100000, shiftl: 0, shiftr: 5 }));
    assert_eq!(operations(0, 4).unwrap(), vec!(Op { mask: 0b11110000, shiftl: 0, shiftr: 4 }));
    assert_eq!(operations(0, 5).unwrap(), vec!(Op { mask: 0b11111000, shiftl: 0, shiftr: 3 }));
    assert_eq!(operations(0, 6).unwrap(), vec!(Op { mask: 0b11111100, shiftl: 0, shiftr: 2 }));
    assert_eq!(operations(0, 7).unwrap(), vec!(Op { mask: 0b11111110, shiftl: 0, shiftr: 1 }));
    assert_eq!(operations(0, 8).unwrap(), vec!(Op { mask: 0b11111111, shiftl: 0, shiftr: 0 }));
    assert_eq!(operations(0, 9).unwrap(), vec!(Op { mask: 0b11111111, shiftl: 1, shiftr: 0 },
                                               Op { mask: 0b10000000, shiftl: 0, shiftr: 7 }));
    assert_eq!(operations(0, 10).unwrap(), vec!(Op { mask: 0b11111111, shiftl: 2, shiftr: 0 },
                                                Op { mask: 0b11000000, shiftl: 0, shiftr: 6 }));

    assert_eq!(operations(1, 1).unwrap(), vec!(Op { mask: 0b01000000, shiftl: 0, shiftr: 6 }));
    assert_eq!(operations(1, 2).unwrap(), vec!(Op { mask: 0b01100000, shiftl: 0, shiftr: 5 }));
    assert_eq!(operations(1, 3).unwrap(), vec!(Op { mask: 0b01110000, shiftl: 0, shiftr: 4 }));
    assert_eq!(operations(1, 4).unwrap(), vec!(Op { mask: 0b01111000, shiftl: 0, shiftr: 3 }));
    assert_eq!(operations(1, 5).unwrap(), vec!(Op { mask: 0b01111100, shiftl: 0, shiftr: 2 }));
    assert_eq!(operations(1, 6).unwrap(), vec!(Op { mask: 0b01111110, shiftl: 0, shiftr: 1 }));
    assert_eq!(operations(1, 7).unwrap(), vec!(Op { mask: 0b01111111, shiftl: 0, shiftr: 0 }));
    assert_eq!(operations(1, 8).unwrap(), vec!(Op { mask: 0b01111111, shiftl: 1, shiftr: 0 },
                                               Op { mask: 0b10000000, shiftl: 0, shiftr: 7 }));
    assert_eq!(operations(1, 9).unwrap(), vec!(Op { mask: 0b01111111, shiftl: 2, shiftr: 0 },
                                               Op { mask: 0b11000000, shiftl: 0, shiftr: 6 }));

    assert_eq!(operations(8, 1), None);
    assert_eq!(operations(3, 0), None);
    assert_eq!(operations(3, 65), None);

    assert_eq!(operations(3, 33).unwrap(), vec!(Op { mask: 0b00011111, shiftl: 28, shiftr: 0 },
                                                Op { mask: 0b11111111, shiftl: 20, shiftr: 0 },
                                                Op { mask: 0b11111111, shiftl: 12, shiftr: 0 },
                                                Op { mask: 0b11111111, shiftl: 4, shiftr: 0 },
                                                Op { mask: 0b11110000, shiftl: 0, shiftr: 4 }));
}
//#[inline(always)]
//fn get_field<T>(packet: &[u8], offset: usize, size: usize, endianness: Endianness) -> T {
//    let packet = packet[offset..];
//}

#[plugin_registrar]
pub fn plugin_registrar(registry: &mut Registry) {
    registry.register_syntax_extension(token::intern("packet"),
                                       Decorator(Box::new(generate_packet)));
}

fn generate_packet(ecx: &mut ExtCtxt,
                   span: Span,
                   _meta_item: &ast::MetaItem,
                   item: &ast::Item,
                   mut push: Box<FnMut(P<ast::Item>)>) {
    match item.node {
        ast::ItemEnum(..) => unimplemented!(),
        ast::ItemStruct(ref sd, ref _gs) => {
            let name = item.ident.as_str().to_string();
            push(generate_header_struct(ecx, format!("{}Header", name), false));
            push(generate_header_struct(ecx, format!("Mutable{}Header", name), true));

            // TODO impl Packet for ...
            let ref fields = sd.fields;
            for ref field in fields {
                if let Some(name) = field.node.ident() {
                    println!("field: {:?}", name.as_str());
                } else {
                    ecx.span_err(field.span, "all fields in a packet must be named");
                }
            }
        },
        _ => {
            ecx.span_err(span, "#[packet] may only be used with enums and structs");
        }
    }
}

fn generate_header_struct(ecx: &mut ExtCtxt, name: String, mut_: bool) -> P<ast::Item> {
    let mutable = if mut_ {
        " mut"
    } else {
        ""
    };

    ecx.parse_item(format!("//#[derive(Copy)] // FIXME?
struct {}<'p> {{
    packet: &'p{} [u8],
}}", name, mutable))
//    let header_name_ident = token::str_to_ident(name.as_slice());
//    let field = ast::StructField_ {
//        kind: NamedField(token::str_to_ident("packet"), ast::Visibility::Inherited),
//        id: ast::DUMMY_NODE_ID,
//        ty: ty,
//        attrs: vec!(),
//    };
//    let header_fields = ast::StructDef {
//        fields: vec!(Spanned { node: field, span: span }),
//        ctor_id: None
//    };
//    let lifetime_param = ast::LifetimeDef {
//        lifetime: ast::Lifetime {
//            id: ast::DUMMY_NODE_ID,
//            span: span,
//            name: token::intern("p"),
//        },
//        bounds: vec!(),
//    };
//    let generics = ast::Generics {
//        lifetimes: vec!(lifetime_param),
//        ty_params: OwnedSlice::empty(),
//        where_clause: ast::WhereClause {
//            id: ast::DUMMY_NODE_ID,
//            predicates: vec!()
//        }
//    };
//
//    ecx.item_struct_poly(span, header_name_ident, header_fields, generics)
}

fn generate_header_impls(ecx: &mut ExtCtxt, span: Span, name: String) -> P<ast::Item> {
    let imp = ecx.parse_item(format!("impl<'a> {name}<'a> {{
    pub fn new(packet: &'p mut [u8]) -> {name}<'p> {{
        {name} {{ packet: packet }}
    }}
}}", name = name));

    // FIXME generate getters/setters

    imp
}
