// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
// Copyright (c) 2021 Pierre Chifflier <chifflier@wzdftpd.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The pnet_macros crate provides the `#[packet]` macro and compiler plugin, which is used to
//! specify the format of on-the-wire packets, and automatically generate zero-copy accessors and
//! mutators for the fields. It is used as follows:
//!
//! ```
//! /// Import the `Packet` custom derive attribute
//! use pnet_macros::Packet;
//! /// This module contains a list of type aliases which may be used
//! use pnet_macros_support::types::{u4, u12be};
//!
//! /// Packets are specified in the same way as normal Rust structs, but with a `#[packet]`
//! /// attribute.
//! #[derive(Packet)]
//! pub struct Example {
//!     // This is a simple field which contains a 4-bit, unsigned integer.
//!     // Note that `u4` is simply an alias for `u8` - the name is a hint
//!     // to the compiler plugin, it is NOT a usable 4 bit type!
//!     simple_field1: u4,
//!
//!     // This specifies that `simple_field2` should be a 12-bit field,
//!     // with bits stored in big endian
//!     simple_field2: u12be,
//!
//!     // All packets must specify a `#[payload]`, which should be a
//!     // `Vec<u8>`. This represents the packet's payload, for example in
//!     // an IPv4 packet, the payload could be a UDP packet, or in a UDP
//!     // packet the payload could be the application data. All the
//!     // remaining space in the packet is considered to be the payload
//!     // (this doesn't have to be the case, see the documentation for
//!     // `#[payload]` below.
//!     #[payload]
//!     payload: Vec<u8>
//! }
//! ```
//! A number of things will then be generated. You can see this in action in the documentation and
//! source of each of the packet types in the `pnet::packet` module. Things generated include
//! (assuming the `Example` struct from above):
//!
//!  * An `ExamplePacket<'p>` structure, which is used for receiving packets on the network.
//!    This structure contains:
//!      - A method, `pub fn new<'p>(packet: &'p [u8]) -> ExamplePacket<'p>`, used for the
//!        construction of an `ExamplePacket`, given a buffer to store it. The buffer should be
//!        long enough to contain all the fields in the packet.
//!      - A method, `pub fn to_immutable<'p>(&'p self) -> ExamplePacket<'p>`, which is simply an
//!        identity function. It exists for consistency with `MutableExamplePacket`.
//!      - A number of accessor methods, of the form `pub get_{field_name}(&self) -> {field_type}`,
//!        which will retrieve the host representation of the on-the-wire value.
//!  * A `MutableExamplePacket<'p>` structure, which is used when sending packets on the network.
//!    This structure contains:
//!      - A method, `pub fn new<'p>(packet: &'p mut [u8]) -> MutableExamplePacket<'p>`, used for
//!        the construction of a `MutableExamplePacket`, given a buffer to store it. The buffer
//!        should be long enough to contain all the fields in the packet.
//!      - A method, `pub fn to_immutable<'p>(&'p self) -> ExamplePacket<'p>`, which converts from
//!        a `MutableExamplePacket` to an `ExamplePacket`
//!      - A method, `pub fn populate(&mut self, packet: Example)`, which, given an `Example`
//!        struct, will populate the `MutableExamplePacket` with the values from the `Example`
//!        struct.
//!      - A number of accessor methods, of the form `pub get_{field_name}(&self) -> {field_type}`,
//!        which will retrieve the host representation of the on-the-wire value.
//!      - A number of mutator methods, of the form `pub set_{field_name}(&mut self,
//!        val: {field_type})`, which will take a host value, convert it to the required
//!        on-the-wire format, and store it in the buffer which backs the `MutableExamplePacket`.
//!  * A number of trait implementations for each of the `MutableExamplePacket` and `ExamplePacket`
//!    structures. These include:
//!      - `pnet::packet::Packet` (`ExamplePacket` and `MutableExamplePacket`)
//!      - `pnet::packet::MutablePacket` (`MutableExamplePacket` only)
//!      - `core::fmt::Debug` (`ExamplePacket` and `MutableExamplePacket`)
//!      - `pnet::packet::FromPacket` (`ExamplePacket` and `MutableExamplePacket`)
//!      - `pnet::packet::PacketSize` (`ExamplePacket` and `MutableExamplePacket`)
//!  * An `ExampleIterator` structure, which implements `core::iter::Iterator`, to allow iterating
//!    over vectors of `ExamplePacket` contained within another packet. Used internally.
//!
//! ## Attributes
//!
//! There are a number of attributes which fields may have, these include:
//!
//!  * \#[length_fn = "function_name"]
//!
//!    This attribute is used to enable variable length fields. To specify a variable length field,
//!    it should have the type `Vec<T>`. It must have the `#[length_fn]` (or #\[length\]) attribute,
//!    which specifies a function name to calculate the length of the field. The signature for the
//!    length function should be
//!    `fn {function_name}<'a>(example_packet: &ExamplePacket<'a>) -> usize`, substituting
//!    `&ExamplePacket<'a>` for the appropriately named packet type for your structure. You may
//!    access whichever fields are required to calculate the length of the field. The returned
//!    value should be a number of bytes that the field uses.
//!
//!    The type contained in the vector may either be one of the primitive types specified in
//!    `pnet_macros::types`, or another structure marked with #[derive(Packet)], for example
//!    `Vec<Example>`.
//!
//!  * \#[length = "arithmetic expression"]
//!
//!    This attribute is used to enable variable length fields. To specify a variable length field,
//!    it should have the type `Vec<T>`. It must have the `#[length]` (or #\[length_fn\]) attribute,
//!    which specifies an arithmetic expression to calculate the length of the field. Only field
//!    names, constants, integers, basic arithmetic expressions (+ - * / %) and parentheses are
//!    in the expression. An example would be `#[length = "field_name + CONSTANT - 4]`.
//!
//!    The type contained in the vector may either be one of the primitive types specified in
//!    `pnet_macros::types`, or another structure marked with #[derive(Packet)], for example
//!    `Vec<Example>`.
//!
//!  * \#\[payload\]
//!
//!    This attribute specifies the payload associated with the packet. This should specify the
//!    data associated with the packet. It may be used in two places:
//!      - The last field in the packet, in which case it is assumed to use the remaining length of
//!        the buffer containing the packet
//!      - Another location in the packet, in which case the `#[length_fn]` attribute must also be
//!        specified to give the length of the payload.
//!    If the packet has no payload, you must still specify this attribute, but you can provide a
//!    `#[length_fn]` attribute returning zero.
//!
//!  * \#[construct_with(<primitive type>, ...)]
//!
//!    Unfortunately, compiler plugins do not currently have access to type information during the
//!    decoration stage (where all of the above is generated), so this attribute is required. This
//!    must be used for all fields which are neither primitive types, nor vectors of primitive
//!    types. Three things are required when using `#[construct_with]`:
//!      - The field type must have a method `new`, which takes one or more parameters of primitive
//!        types.
//!      - The field must be annotated with the `#[construct_with(...)]` attribute, specifying a
//!        list of types identical to those taken by the `new` method.
//!      - The `pnet::packet::ToPrimitiveValues` trait must be implemented for the field type,
//!        which must return a tuple of the primitive types specified in the parameters to the
//!        `#[construct_with(...)]` attribute, and in the `new` method.

#![deny(missing_docs)]
// #![cfg_attr(feature = "clippy", feature(plugin))]
// #![cfg_attr(feature = "clippy", plugin(clippy))]
// #![cfg_attr(feature = "clippy", allow(let_and_return))]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Visibility};

mod decorator;
mod util;

/// The entry point for the `derive(Packet)` custom derive
#[proc_macro_derive(Packet, attributes(construct_with, length, length_fn, payload))]
pub fn derive_packet(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    // ensure struct is public
    match ast.vis {
        Visibility::Public(_) => (),
        _ => {
            let ts = syn::Error::new(ast.ident.span(), "#[packet] structs must be public")
                .to_compile_error();
            return ts.into();
        }
    }
    let name = &ast.ident;
    let s = match &ast.data {
        syn::Data::Struct(ref s) => decorator::generate_packet(s, name.to_string()),
        _ => panic!("Only structs are supported"),
    };
    match s {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// The entry point for the `packet` proc_macro_attribute
#[proc_macro_attribute]
pub fn packet(_attrs: TokenStream, code: TokenStream) -> TokenStream {
    // let _attrs = parse_macro_input!(attrs as AttributeArgs);
    let input = parse_macro_input!(code as DeriveInput);
    // enhancement: if input already has Clone and/or Debug, do not add them
    let s = quote! {
        #[derive(::pnet_macros::Packet, Clone, Debug)]
        #[allow(unused_attributes)]
        #input
    };
    s.into()
}
