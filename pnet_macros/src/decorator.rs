// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
// Copyright (c) 2021 Pierre Chifflier <chifflier@wzdftpd.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Implements the #\[packet\] decorator.

use crate::util::{
    operations, to_little_endian, to_mutator, Endianness, GetOperation, SetOperation,
};
use core::iter::FromIterator;
use proc_macro2::{Group, Span};
use quote::{quote, ToTokens};
use regex::Regex;
use syn::{spanned::Spanned, Error};

#[derive(Debug, PartialEq, Eq)]
enum EndiannessSpecified {
    No,
    Yes,
}

/// Lower and upper bounds of a payload.
/// Represented as strings since they may involve functions.
struct PayloadBounds {
    lower: String,
    upper: String,
}

#[derive(Clone, Debug, PartialEq)]
enum Type {
    /// Any of the `u*` types from `pnet_macros::types::*`.
    Primitive(String, usize, Endianness),
    /// Any type of the form `Vec<T>`.
    Vector(Box<Type>),
    /// Any type which isn't a primitive or a vector.
    Misc(String),
}

#[derive(Clone, Debug)]
struct Field {
    name: String,
    span: Span,
    ty: Type,
    packet_length: Option<String>,
    struct_length: Option<String>,
    is_payload: bool,
    construct_with: Option<Vec<Type>>,
}

#[derive(Clone, Debug)]
pub struct Packet {
    base_name: String,
    fields: Vec<Field>,
}

impl Packet {
    fn packet_name_mut(&self) -> String {
        format!("Mutable{}Packet", self.base_name)
    }
    fn packet_name(&self) -> String {
        format!("{}Packet", self.base_name)
    }
}

#[inline]
pub fn generate_packet(
    s: &syn::DataStruct,
    name: String,
) -> Result<proc_macro2::TokenStream, Error> {
    let packet = make_packet(s, name)?;
    let structs = generate_packet_struct(&packet);
    let (ts_packet_impls, payload_bounds, packet_size) = generate_packet_impls(&packet)?;
    let ts_size_impls = generate_packet_size_impls(&packet, &packet_size)?;
    let ts_trait_impls = generate_packet_trait_impls(&packet, &payload_bounds)?;
    let ts_iterables = generate_iterables(&packet)?;
    let ts_converters = generate_converters(&packet)?;
    let ts_debug_impls = generate_debug_impls(&packet)?;
    let tts = quote! {
        #structs
        #ts_packet_impls
        #ts_size_impls
        #ts_trait_impls
        #ts_iterables
        #ts_converters
        #ts_debug_impls
    };
    Ok(tts)
}

#[inline]
fn generate_packet_struct(packet: &Packet) -> proc_macro2::TokenStream {
    let items = &[
        (packet.packet_name(), "PacketData"),
        (packet.packet_name_mut(), "MutPacketData"),
    ];
    let tts: Vec<_> = items
        .iter()
        .map(|(name, packet_data)| {
            let name = syn::Ident::new(&name, Span::call_site());
            let packet_data = syn::Ident::new(packet_data, Span::call_site());
            quote! {
                #[derive(PartialEq)]
                /// A structure enabling manipulation of on the wire packets
                pub struct #name<'p> {
                    packet: ::pnet_macros_support::packet::#packet_data<'p>,
                }
            }
        })
        .collect();
    quote! {
        #(#tts)*
    }
}

#[inline]
fn make_type(ty_str: String, endianness_important: bool) -> Result<Type, String> {
    if let Some((size, endianness, spec)) = parse_ty(&ty_str[..]) {
        if !endianness_important || size <= 8 || spec == EndiannessSpecified::Yes {
            Ok(Type::Primitive(ty_str, size, endianness))
        } else {
            Err("endianness must be specified for types of size >= 8".to_owned())
        }
    } else if ty_str.starts_with("Vec<") {
        let ty = make_type(
            String::from(&ty_str[4..ty_str.len() - 1]),
            endianness_important,
        );
        match ty {
            Ok(ty) => Ok(Type::Vector(Box::new(ty))),
            Err(e) => Err(e),
        }
    } else if ty_str.starts_with("&") {
        Err(format!("invalid type: {}", ty_str))
    } else {
        Ok(Type::Misc(ty_str))
    }
}

#[inline]
fn make_packet(s: &syn::DataStruct, name: String) -> Result<Packet, Error> {
    let mut fields = Vec::new();
    let mut payload_span = None;
    let sfields = &s.fields;
    for field in sfields {
        let field_name = match &field.ident {
            Some(name) => name.to_string(),
            None => {
                return Err(Error::new(
                    field.ty.span(),
                    "all fields in a packet must be named",
                ));
            }
        };
        let mut construct_with = None;
        let mut is_payload = false;
        let mut packet_length = None;
        let mut struct_length = None;
        for attr in &field.attrs {
            match attr.meta {
                syn::Meta::Path(ref p) => {
                    if let Some(ident) = p.get_ident() {
                        if ident == "payload" {
                            if payload_span.is_some() {
                                return Err(Error::new(
                                    p.span(),
                                    "packet may not have multiple payloads",
                                ));
                            }
                            is_payload = true;
                            payload_span = Some(field.span());
                        }
                    }
                }
                syn::Meta::NameValue(ref name_value) => {
                    if let Some(ident) = name_value.path.get_ident() {
                        if ident == "length_fn" {
                            if let syn::Expr::Lit(syn::ExprLit {
                                lit: syn::Lit::Str(ref s),
                                ..
                            }) = name_value.value
                            {
                                packet_length = Some(s.value() + "(&_self.to_immutable())");
                            } else {
                                return Err(Error::new(
                                    name_value.path.span(),
                                    "#[length_fn] should be used as #[length_fn = \
                                               \"name_of_function\"]",
                                ));
                            }
                        } else if ident == "length" {
                            // get literal
                            if let syn::Expr::Lit(syn::ExprLit {
                                lit: syn::Lit::Str(ref s),
                                ..
                            }) = name_value.value
                            {
                                let field_names: Vec<String> = sfields
                                    .iter()
                                    .filter_map(|field| {
                                        field.ident.as_ref().map(|name| name.to_string()).and_then(
                                            |name| {
                                                if name == field_name {
                                                    None
                                                } else {
                                                    Some(name)
                                                }
                                            },
                                        )
                                    })
                                    .collect();
                                // Convert to tokens
                                let expr = s.parse::<syn::Expr>()?;
                                let tts = expr.to_token_stream();
                                let tt_tokens: Vec<_> = tts.into_iter().collect();
                                // Parse and replace fields
                                let tokens_packet = parse_length_expr(&tt_tokens, &field_names)?;
                                let parsed = quote! { #(#tokens_packet)* };
                                packet_length = Some(parsed.to_string());
                            } else {
                                return Err(Error::new(
                                    name_value.value.span(),
                                    "#[length] should be used as #[length = \
                                                \"field_name and/or arithmetic expression\"]",
                                ));
                            }
                        } else {
                            return Err(Error::new(
                                ident.span(),
                                &format!("Unknown meta/namevalue option '{}'", ident),
                            ));
                        }
                    }
                }
                syn::Meta::List(ref l) => {
                    if let Some(ident) = l.path.get_ident() {
                        if ident == "construct_with" {
                            let mut some_construct_with = Vec::new();

                            l.parse_nested_meta(|meta| {
                                if let Some(ident) = meta.path.get_ident() {
                                    // #[construct_with(<type>,...)]
                                    let ty_str = ident.to_string();
                                    match make_type(ty_str, false) {
                                        Ok(ty) => {
                                            some_construct_with.push(ty);
                                            Ok(())
                                        }
                                        Err(e) => Err(meta.error(e)),
                                    }
                                } else {
                                    // Not an ident. Something else, likely a path.
                                    Err(meta.error("expected ident"))
                                }
                            })
                            .map_err(|mut err| {
                                err.combine(Error::new(
                                    l.span(),
                                    "#[construct_with] should be of the form \
                                        #[construct_with(<primitive types>)]",
                                ));
                                err
                            })?;

                            if some_construct_with.is_empty() {
                                return Err(Error::new(
                                    l.span(),
                                    "#[construct_with] must have at least one argument",
                                ));
                            }
                            construct_with = Some(some_construct_with);
                        } else {
                            return Err(Error::new(
                                ident.span(),
                                &format!("unknown attribute: {}", ident),
                            ));
                        }
                    } else {
                        return Err(Error::new(
                            l.path.span(),
                            "meta-list attribute has unexpected type (not an ident)",
                        ));
                    }
                }
            }
        }

        let ty = match make_type(ty_to_string(&field.ty), true) {
            Ok(ty) => ty,
            Err(e) => {
                return Err(Error::new(field.ty.span(), &format!("{}", e)));
            }
        };

        match ty {
            Type::Vector(_) => {
                struct_length = if let Some(construct_with) = construct_with.as_ref() {
                    let mut inner_size = 0;
                    for arg in construct_with.iter() {
                        if let Type::Primitive(ref _ty_str, size, _endianness) = *arg {
                            inner_size += size;
                        } else {
                            return Err(Error::new(
                                field.span(),
                                "arguments to #[construct_with] must be primitives",
                            ));
                        }
                    }
                    if inner_size % 8 != 0 {
                        return Err(Error::new(
                                field.span(),
                                "types in #[construct_with] for vec must be add up to a multiple of 8 bits",
                                ));
                    }
                    inner_size /= 8; // bytes not bits

                    Some(format!("_packet.{}.len() * {}", field_name, inner_size).to_owned())
                } else {
                    Some(format!("_packet.{}.len()", field_name).to_owned())
                };
                if !is_payload && packet_length.is_none() {
                    return Err(Error::new(
                        field.ty.span(),
                        "variable length field must have #[length = \"\"] or \
                                  #[length_fn = \"\"] attribute",
                    ));
                }
            }
            Type::Misc(_) => {
                if construct_with.is_none() {
                    return Err(Error::new(
                        field.ty.span(),
                        "non-primitive field types must specify #[construct_with]",
                    ));
                }
            }
            _ => {}
        }

        fields.push(Field {
            name: field_name,
            span: field.span(),
            ty,
            packet_length,
            struct_length,
            is_payload,
            construct_with,
        });
    }

    if payload_span.is_none() {
        return Err(Error::new(
            Span::call_site(),
            "#[packet]'s must contain a payload",
        ));
    }

    Ok(Packet {
        base_name: name,
        fields,
    })
}

/// Return the processed length expression for a packet.
#[inline]
fn parse_length_expr(
    tts: &[proc_macro2::TokenTree],
    field_names: &[String],
) -> Result<Vec<proc_macro2::TokenTree>, Error> {
    use proc_macro2::TokenTree;
    let error_msg = "Only field names, constants, integers, basic arithmetic expressions \
                     (+ - * / %) and parentheses are allowed in the \"length\" attribute";
    let mut needs_constant: Option<Span> = None;
    let mut has_constant = false;
    let mut tokens_packet = Vec::new();
    for tt_token in tts {
        match tt_token {
            TokenTree::Ident(name) => {
                if name.to_string().chars().any(|c| c.is_lowercase()) {
                    if field_names.contains(&name.to_string()) {
                        let tts: syn::Expr =
                            syn::parse_str(&format!("_self.get_{}() as usize", name))?;
                        let mut modified_packet_tokens: Vec<_> =
                            tts.to_token_stream().into_iter().collect();
                        tokens_packet.append(&mut modified_packet_tokens);
                    } else {
                        if let None = needs_constant {
                            needs_constant = Some(tt_token.span());
                        }
                        tokens_packet.push(tt_token.clone());
                    }
                }
                // Constants are only recognized if they are all uppercase
                else {
                    let tts: syn::Expr = syn::parse_str(&format!("{} as usize", name))?;
                    let mut modified_packet_tokens: Vec<_> =
                        tts.to_token_stream().into_iter().collect();
                    tokens_packet.append(&mut modified_packet_tokens);
                    has_constant = true;
                }
            }
            TokenTree::Punct(_) => {
                tokens_packet.push(tt_token.clone());
            }
            TokenTree::Literal(lit) => {
                // must be an integer
                if syn::parse_str::<syn::LitInt>(&lit.to_string()).is_err() {
                    return Err(Error::new(lit.span(), error_msg));
                }
                tokens_packet.push(tt_token.clone());
            }
            TokenTree::Group(ref group) => {
                let ts: Vec<_> = group.stream().into_iter().collect();
                let tts = parse_length_expr(&ts, field_names)?;
                let mut new_group = Group::new(
                    group.delimiter(),
                    proc_macro2::TokenStream::from_iter(tts.into_iter()),
                );
                new_group.set_span(group.span());
                let tt = TokenTree::Group(new_group);
                tokens_packet.push(tt);
            }
        };
    }

    if let Some(span) = needs_constant {
        if !has_constant {
            return Err(Error::new(
                span,
                "Field name must be a member of the struct and not the field itself",
            ));
        }
    }

    Ok(tokens_packet)
}

#[inline]
fn generate_packet_impl(
    packet: &Packet,
    mutable: bool,
    name: String,
) -> Result<(proc_macro2::TokenStream, PayloadBounds, String), Error> {
    let mut bit_offset = 0;
    let mut offset_fns_packet = Vec::new();
    let mut offset_fns_struct = Vec::new();
    let mut accessors = "".to_owned();
    let mut mutators = "".to_owned();
    let mut payload_bounds = None;
    for (idx, field) in packet.fields.iter().enumerate() {
        let mut co = current_offset(bit_offset, &offset_fns_packet[..]);

        if field.is_payload {
            let mut upper_bound_str = "".to_owned();
            if field.packet_length.is_some() {
                upper_bound_str =
                    format!("{} + {}", co.clone(), field.packet_length.as_ref().unwrap());
            } else {
                if idx != packet.fields.len() - 1 {
                    return Err(Error::new(
                        field.span,
                        "#[payload] must specify a #[length_fn], unless it is the \
                                        last field of a packet",
                    ));
                }
            }
            payload_bounds = Some(PayloadBounds {
                lower: co.clone(),
                upper: upper_bound_str,
            });
        }
        match field.ty {
            Type::Primitive(ref ty_str, size, endianness) => {
                let mut ops = operations(bit_offset % 8, size).unwrap();
                let target_endianness = if cfg!(target_endian = "little") {
                    Endianness::Little
                } else {
                    Endianness::Big
                };

                if endianness == Endianness::Little
                    || (target_endianness == Endianness::Little && endianness == Endianness::Host)
                {
                    ops = to_little_endian(ops);
                }

                mutators = mutators
                    + &generate_mutator_str(
                        &field.name[..],
                        &ty_str[..],
                        &co[..],
                        &to_mutator(&ops[..])[..],
                        None,
                    )[..];
                accessors = accessors
                    + &generate_accessor_str(&field.name[..], &ty_str[..], &co[..], &ops[..], None)
                        [..];
                bit_offset += size;
            }
            Type::Vector(ref inner_ty) => handle_vector_field(
                &field,
                &mut bit_offset,
                &offset_fns_packet[..],
                &mut co,
                &name,
                &mut mutators,
                &mut accessors,
                inner_ty,
            )?,
            Type::Misc(ref ty_str) => handle_misc_field(
                &field,
                &mut bit_offset,
                &offset_fns_packet[..],
                &mut co,
                &name,
                &mut mutators,
                &mut accessors,
                &ty_str,
            )?,
        }
        if field.packet_length.is_some() {
            offset_fns_packet.push(field.packet_length.as_ref().unwrap().clone());
        }
        if field.struct_length.is_some() {
            offset_fns_struct.push(field.struct_length.as_ref().unwrap().clone());
        }
    }

    fn generate_set_fields(packet: &Packet) -> String {
        let mut set_fields = String::new();
        for field in &packet.fields {
            match field.ty {
                Type::Vector(_) => {
                    set_fields = set_fields
                        + &format!("_self.set_{field}(&packet.{field});\n", field = field.name)[..];
                }
                _ => {
                    set_fields = set_fields
                        + &format!("_self.set_{field}(packet.{field});\n", field = field.name)[..];
                }
            }
        }

        set_fields
    }

    let populate = if mutable {
        let set_fields = generate_set_fields(&packet);
        let imm_name = packet.packet_name();
        format!(
            "/// Populates a {name}Packet using a {name} structure
             #[inline]
             #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
             pub fn populate(&mut self, packet: &{name}) {{
                 let _self = self;
                 {set_fields}
             }}",
            name = &imm_name[..imm_name.len() - 6],
            set_fields = set_fields
        )
    } else {
        "".to_owned()
    };

    // If there are no variable length fields defined, then `_packet` is not used, hence
    // the leading underscore
    let packet_size_struct = format!(
        "/// The size (in bytes) of a {base_name} instance when converted into
            /// a byte-array
            #[inline]
            pub fn packet_size(_packet: \
                 &{base_name}) -> usize {{
                {struct_size}
            }}",
        base_name = packet.base_name,
        struct_size = current_offset(bit_offset, &offset_fns_struct[..])
    );

    let byte_size = if bit_offset % 8 == 0 {
        bit_offset / 8
    } else {
        (bit_offset / 8) + 1
    };

    let s = format!("impl<'a> {name}<'a> {{
        /// Constructs a new {name}. If the provided buffer is less than the minimum required
        /// packet size, this will return None.
        #[inline]
        pub fn new<'p>(packet: &'p {mut} [u8]) -> Option<{name}<'p>> {{
            if packet.len() >= {name}::minimum_packet_size() {{
                use ::pnet_macros_support::packet::{cap_mut}PacketData;
                Some({name} {{ packet: {cap_mut}PacketData::Borrowed(packet) }})
            }} else {{
                None
            }}
        }}

        /// Constructs a new {name}. If the provided buffer is less than the minimum required
        /// packet size, this will return None. With this constructor the {name} will
        /// own its own data and the underlying buffer will be dropped when the {name} is.
        pub fn owned(packet: Vec<u8>) -> Option<{name}<'static>> {{
            if packet.len() >= {name}::minimum_packet_size() {{
                use ::pnet_macros_support::packet::{cap_mut}PacketData;
                Some({name} {{ packet: {cap_mut}PacketData::Owned(packet) }})
            }} else {{
                None
            }}
        }}

        /// Maps from a {name} to a {imm_name}
        #[inline]
        pub fn to_immutable<'p>(&'p self) -> {imm_name}<'p> {{
            use ::pnet_macros_support::packet::PacketData;
            {imm_name} {{ packet: PacketData::Borrowed(self.packet.as_slice()) }}
        }}

        /// Maps from a {name} to a {imm_name} while consuming the source
        #[inline]
        pub fn consume_to_immutable(self) -> {imm_name}<'a> {{
            {imm_name} {{ packet: self.packet.to_immutable() }}
        }}

        /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
        /// of the fixed-size fields.
        #[inline]
        pub const fn minimum_packet_size() -> usize {{
            {byte_size}
        }}

        {packet_size_struct}

        {populate}

        {accessors}

        {mutators}
    }}", name = name,
    imm_name = packet.packet_name(),
    mut = if mutable { "mut" } else { "" },
    cap_mut = if mutable { "Mut" } else { "" },
    byte_size = byte_size,
    accessors = accessors,
    mutators = if mutable { &mutators[..] } else { "" },
    populate = populate,
    packet_size_struct = packet_size_struct
        );

    let stmt: syn::Stmt = syn::parse_str(&s).expect("parse fn generate_packet_impl failed");
    let ts = quote! {
        #stmt
    };

    Ok((
        ts,
        payload_bounds.unwrap(),
        current_offset(bit_offset, &offset_fns_packet[..]),
    ))
}

#[inline]
fn generate_packet_impls(
    packet: &Packet,
) -> Result<(proc_macro2::TokenStream, PayloadBounds, String), Error> {
    let mut ret = None;
    let mut tts = Vec::new();
    for (mutable, name) in vec![
        (false, packet.packet_name()),
        (true, packet.packet_name_mut()),
    ] {
        let (tokens, bounds, size) = generate_packet_impl(packet, mutable, name)?;
        tts.push(tokens);
        ret = Some((bounds, size));
    }
    let tokens = quote! { #(#tts)* };

    ret.map(|(bounds, size)| (tokens, bounds, size))
        .ok_or_else(|| Error::new(Span::call_site(), "generate_packet_impls failed"))
}

#[inline]
fn generate_packet_size_impls(
    packet: &Packet,
    size: &str,
) -> Result<proc_macro2::TokenStream, Error> {
    let tts: Result<Vec<_>, _> = [packet.packet_name(), packet.packet_name_mut()]
        .iter()
        .map(|name| {
            let s = format!(
                "
                impl<'a> ::pnet_macros_support::packet::PacketSize for {name}<'a> {{
                    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                    fn packet_size(&self) -> usize {{
                        let _self = self;
                        {size}
                    }}
                }}
            ",
                name = name,
                size = size
            );
            syn::parse_str::<syn::Stmt>(&s)
        })
        .collect();
    let tts = tts?;
    Ok(quote! { #(#tts)* })
}

#[inline]
fn generate_packet_trait_impls(
    packet: &Packet,
    payload_bounds: &PayloadBounds,
) -> Result<proc_macro2::TokenStream, Error> {
    let items = [
        (packet.packet_name_mut(), "Mutable", "_mut", "mut"),
        (packet.packet_name_mut(), "", "", ""),
        (packet.packet_name(), "", "", ""),
    ];
    let tts: Result<Vec<_>, _> = items
        .iter()
        .map(|(name, mutable, u_mut, mut_)| {
            let mut pre = "".to_owned();
            let mut start = "".to_owned();
            let mut end = "".to_owned();
            if !payload_bounds.lower.is_empty() {
                pre = pre + &format!("let start = {};", payload_bounds.lower)[..];
                start = "start".to_owned();
            }
            if !payload_bounds.upper.is_empty() {
                pre = pre
                    + &format!(
                        "let end = ::core::cmp::min({}, _self.packet.len());",
                        payload_bounds.upper
                    )[..];
                end = "end".to_owned();
            }
            let s = format!(
                "impl<'a> ::pnet_macros_support::packet::{mutable}Packet for {name}<'a> {{
            #[inline]
            fn packet{u_mut}<'p>(&'p {mut_} self) -> &'p {mut_} [u8] {{ &{mut_} self.packet[..] }}

            #[inline]
            #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
            fn payload{u_mut}<'p>(&'p {mut_} self) -> &'p {mut_} [u8] {{
                let _self = self;
                {pre}
                if _self.packet.len() <= {start} {{
                    return &{mut_} [];
                }}
                &{mut_} _self.packet[{start}..{end}]
            }}
        }}",
                name = name,
                start = start,
                end = end,
                pre = pre,
                mutable = mutable,
                u_mut = u_mut,
                mut_ = mut_
            );
            syn::parse_str::<syn::Stmt>(&s)
        })
        .collect();
    let tts = tts?;
    Ok(quote! { #(#tts)* })
}

#[inline]
fn generate_iterables(packet: &Packet) -> Result<proc_macro2::TokenStream, Error> {
    let name = &packet.base_name;

    let ts1 = format!(
        "
    /// Used to iterate over a slice of `{name}Packet`s
    pub struct {name}Iterable<'a> {{
        buf: &'a [u8],
    }}
    ",
        name = name
    );

    let ts2 = format!(
        "
    impl<'a> Iterator for {name}Iterable<'a> {{
        type Item = {name}Packet<'a>;

        fn next(&mut self) -> Option<{name}Packet<'a>> {{
            use pnet_macros_support::packet::PacketSize;
            use core::cmp::min;
            if self.buf.len() > 0 {{
                if let Some(ret) = {name}Packet::new(self.buf) {{
                    let start = min(ret.packet_size(), self.buf.len());
                    self.buf = &self.buf[start..];
                    return Some(ret);
                }}
            }}

            None
        }}

        fn size_hint(&self) -> (usize, Option<usize>) {{
            (0, None)
        }}
    }}
    ",
        name = name
    );
    let ts1: syn::Stmt = syn::parse_str(&ts1)?;
    let ts2: syn::Stmt = syn::parse_str(&ts2)?;
    Ok(quote! {
        #ts1
        #ts2
    })
}

#[inline]
fn generate_converters(packet: &Packet) -> Result<proc_macro2::TokenStream, Error> {
    let get_fields = generate_get_fields(packet);

    let tts: Result<Vec<_>, _> = [packet.packet_name(), packet.packet_name_mut()]
        .iter()
        .map(|name| {
            let s = format!(
                "
            impl<'p> ::pnet_macros_support::packet::FromPacket for {packet}<'p> {{
                type T = {name};
                #[inline]
                fn from_packet(&self) -> {name} {{
                    use pnet_macros_support::packet::Packet;
                    let _self = self;
                    {name} {{
                        {get_fields}
                    }}
                }}
            }}",
                packet = name,
                name = packet.base_name,
                get_fields = get_fields
            );
            syn::parse_str::<syn::Stmt>(&s)
        })
        .collect();
    let tts = tts?;
    Ok(quote! { #(#tts)* })
}

#[inline]
fn generate_debug_impls(packet: &Packet) -> Result<proc_macro2::TokenStream, Error> {
    let mut field_fmt_str = String::new();
    let mut get_fields = String::new();

    for field in &packet.fields {
        if !field.is_payload {
            field_fmt_str = format!("{}{} : {{:?}}, ", field_fmt_str, field.name);
            get_fields = format!("{}, _self.get_{}()", get_fields, field.name);
        }
    }

    let tts: Result<Vec<_>, _> = [packet.packet_name(), packet.packet_name_mut()]
        .iter()
        .map(|packet| {
            let s = format!(
                "
        impl<'p> ::core::fmt::Debug for {packet}<'p> {{
            #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
            fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {{
                let _self = self;
                write!(fmt,
                       \"{packet} {{{{ {field_fmt_str} }}}}\"
                       {get_fields}
                )
            }}
        }}",
                packet = packet,
                field_fmt_str = field_fmt_str,
                get_fields = get_fields
            );
            syn::parse_str::<syn::Stmt>(&s)
        })
        .collect();
    let tts = tts?;
    Ok(quote! { #(#tts)* })
}

#[inline]
fn handle_misc_field(
    field: &Field,
    bit_offset: &mut usize,
    offset_fns: &[String],
    co: &mut String,
    name: &str,
    mutators: &mut String,
    accessors: &mut String,
    ty_str: &str,
) -> Result<(), Error> {
    let mut inner_accessors = String::new();
    let mut inner_mutators = String::new();
    let mut get_args = String::new();
    let mut set_args = String::new();
    for (i, arg) in field
        .construct_with
        .as_ref()
        .expect("misc field as ref")
        .iter()
        .enumerate()
    {
        if let Type::Primitive(ref ty_str, size, endianness) = *arg {
            let mut ops = operations(*bit_offset % 8, size).unwrap();
            let target_endianness = if cfg!(target_endian = "little") {
                Endianness::Little
            } else {
                Endianness::Big
            };

            if endianness == Endianness::Little
                || (target_endianness == Endianness::Little && endianness == Endianness::Host)
            {
                ops = to_little_endian(ops);
            }

            let arg_name = format!("arg{}", i);
            inner_accessors = inner_accessors
                + &generate_accessor_str(
                    &arg_name[..],
                    &ty_str[..],
                    &co[..],
                    &ops[..],
                    Some(&name[..]),
                )[..];
            inner_mutators = inner_mutators
                + &generate_mutator_str(
                    &arg_name[..],
                    &ty_str[..],
                    &co[..],
                    &to_mutator(&ops[..])[..],
                    Some(&name[..]),
                )[..];
            get_args = format!("{}get_{}(&self), ", get_args, arg_name);
            set_args = format!("{}set_{}(_self, vals.{});\n", set_args, arg_name, i);
            *bit_offset += size;
            // Current offset needs to be recalculated for each arg
            *co = current_offset(*bit_offset, offset_fns);
        } else {
            return Err(Error::new(
                field.span,
                "arguments to #[construct_with] must be primitives",
            ));
        }
    }
    *mutators = format!(
        "{mutators}
                    /// Set the value of the {name} field.
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                    pub fn set_{name}(&mut self, val: {ty_str}) {{
                        use pnet_macros_support::packet::PrimitiveValues;
                        let _self = self;
                        {inner_mutators}

                        let vals = val.to_primitive_values();

                        {set_args}
                    }}
                    ",
        mutators = &mutators[..],
        name = field.name,
        ty_str = ty_str,
        inner_mutators = inner_mutators,
        set_args = set_args
    );
    let ctor = if field.construct_with.is_some() {
        format!(
            "{} {}::new({})",
            inner_accessors,
            ty_str,
            &get_args[..get_args.len() - 2]
        )
    } else {
        format!(
            "let current_offset = {};
                 {}::new(&_self.packet[current_offset..])",
            co, ty_str
        )
    };
    *accessors = format!(
        "{accessors}
                        /// Get the value of the {name} field
                        #[inline]
                        #[allow(trivial_numeric_casts)]
                        #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                        pub fn get_{name}(&self) -> {ty_str} {{
                            {ctor}
                        }}
                        ",
        accessors = accessors,
        name = field.name,
        ty_str = ty_str,
        ctor = ctor
    );
    Ok(())
}

#[inline]
fn handle_vec_primitive(
    inner_ty_str: &str,
    size: usize,
    field: &Field,
    accessors: &mut String,
    mutators: &mut String,
    co: &mut String,
) -> Result<(), Error> {
    if inner_ty_str == "u8" || (size % 8) == 0 {
        let ops = operations(0, size).unwrap();
        if !field.is_payload {
            let op_strings = generate_accessor_op_str("packet", inner_ty_str, &ops);
            *accessors = format!("{accessors}
                                    /// Get the value of the {name} field (copies contents)
                                    #[inline]
                                    #[allow(trivial_numeric_casts, unused_parens, unused_braces)]
                                    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                    pub fn get_{name}(&self) -> Vec<{inner_ty_str}> {{
                                        use core::cmp::min;
                                        let _self = self;
                                        let current_offset = {co};
                                        let pkt_len = self.packet.len();
                                        let end = min(current_offset + {packet_length}, pkt_len);

                                        let packet = &_self.packet[current_offset..end];
                                        let mut vec: Vec<{inner_ty_str}> = Vec::with_capacity(packet.len() / {size});
                                        let mut co = 0;
                                        for _ in 0..vec.capacity() {{
                                            vec.push({{
                                                {ops}
                                            }});
                                            co += {size};
                                        }}
                                        vec
                                    }}
                                    ",
                                 accessors = accessors,
                                 name = field.name,
                                 co = co,
                                 packet_length = field.packet_length.as_ref().unwrap(),
                                 inner_ty_str = inner_ty_str,
                                 ops = op_strings,
                                 size = size / 8);
        }
        let check_len = if field.packet_length.is_some() {
            format!(
                "let len = {packet_length};
                                             assert!(vals.len() <= len);",
                packet_length = field.packet_length.as_ref().unwrap()
            )
        } else {
            String::new()
        };

        let copy_vals = if inner_ty_str == "u8" {
            // Efficient copy_from_slice (memcpy)
            format!(
                "
                                    _self.packet[current_offset..current_offset + vals.len()]
                                        .copy_from_slice(vals);
                                "
            )
        } else {
            // e.g. Vec<u16> -> Vec<u8>
            let sop_strings = generate_sop_strings(&to_mutator(&ops));
            format!(
                "
                                let mut co = current_offset;
                                for i in 0..vals.len() {{
                                    let val = vals[i];
                                    {sop}
                                    co += {size};
                                }}",
                sop = sop_strings,
                size = size / 8
            )
        };

        *mutators = format!(
            "{mutators}
                                /// Set the value of the {name} field (copies contents)
                                #[inline]
                                #[allow(trivial_numeric_casts)]
                                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                pub fn set_{name}(&mut self, vals: &[{inner_ty_str}]) {{
                                    let mut _self = self;
                                    let current_offset = {co};

                                    {check_len}

                                    {copy_vals}
                               }}",
            mutators = mutators,
            name = field.name,
            co = co,
            check_len = check_len,
            inner_ty_str = inner_ty_str,
            copy_vals = copy_vals
        );
        Ok(())
    } else {
        Err(Error::new(
            field.span,
            "unimplemented variable length field",
        ))
    }
}

#[inline]
fn handle_vector_field(
    field: &Field,
    bit_offset: &mut usize,
    offset_fns: &[String],
    co: &mut String,
    name: &str,
    mutators: &mut String,
    accessors: &mut String,
    inner_ty: &Box<Type>,
) -> Result<(), Error> {
    if !field.is_payload && !field.packet_length.is_some() {
        return Err(Error::new(
            field.span,
            "variable length field must have #[length_fn = \"\"] attribute",
        ));
    }
    if !field.is_payload {
        *accessors = format!("{accessors}
                                /// Get the raw &[u8] value of the {name} field, without copying
                                #[inline]
                                #[allow(trivial_numeric_casts)]
                                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                pub fn get_{name}_raw(&self) -> &[u8] {{
                                    use core::cmp::min;
                                    let _self = self;
                                    let current_offset = {co};
                                    let end = min(current_offset + {packet_length}, _self.packet.len());

                                    &_self.packet[current_offset..end]
                                }}
                                ",
                             accessors = accessors,
                             name = field.name,
                             co = co,
                             packet_length = field.packet_length.as_ref().unwrap());
        *mutators = format!("{mutators}
                                /// Get the raw &mut [u8] value of the {name} field, without copying
                                #[inline]
                                #[allow(trivial_numeric_casts)]
                                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                pub fn get_{name}_raw_mut(&mut self) -> &mut [u8] {{
                                    use core::cmp::min;
                                    let _self = self;
                                    let current_offset = {co};
                                    let end = min(current_offset + {packet_length}, _self.packet.len());

                                    &mut _self.packet[current_offset..end]
                                }}
                                ",
                            mutators = mutators,
                            name = field.name,
                            co = co,
                            packet_length = field.packet_length.as_ref().unwrap());
    }
    match **inner_ty {
        Type::Primitive(ref inner_ty_str, _size, _endianness) => {
            handle_vec_primitive(inner_ty_str, _size, field, accessors, mutators, co)
        }
        Type::Vector(_) => {
            return Err(Error::new(
                field.span,
                "variable length fields may not contain vectors",
            ));
        }
        Type::Misc(ref inner_ty_str) => {
            if let Some(construct_with) = field.construct_with.as_ref() {
                let mut inner_accessors = String::new();
                let mut inner_mutators = String::new();
                let mut get_args = String::new();
                let mut set_args = String::new();
                let mut inner_size = 0;
                for (i, arg) in construct_with.iter().enumerate() {
                    if let Type::Primitive(ref ty_str, size, endianness) = *arg {
                        let mut ops = operations(*bit_offset % 8, size).unwrap();
                        let target_endianness = if cfg!(target_endian = "little") {
                            Endianness::Little
                        } else {
                            Endianness::Big
                        };

                        if endianness == Endianness::Little
                            || (target_endianness == Endianness::Little
                                && endianness == Endianness::Host)
                        {
                            ops = to_little_endian(ops);
                        }

                        inner_size += size;
                        let arg_name = format!("arg{}", i);
                        inner_accessors = inner_accessors
                            + &generate_accessor_with_offset_str(
                                &arg_name[..],
                                &ty_str[..],
                                &co[..],
                                &ops[..],
                                &name[..],
                            )[..];
                        inner_mutators = inner_mutators
                            + &generate_mutator_with_offset_str(
                                &arg_name[..],
                                &ty_str[..],
                                &co[..],
                                &to_mutator(&ops[..])[..],
                                &name[..],
                            )[..];
                        get_args =
                            format!("{}get_{}(&self, additional_offset), ", get_args, arg_name);
                        set_args = format!(
                            "{}set_{}(_self, vals.{}, additional_offset);\n",
                            set_args, arg_name, i
                        );
                        *bit_offset += size;
                        // Current offset needs to be recalculated for each arg
                        *co = current_offset(*bit_offset, offset_fns);
                    } else {
                        return Err(Error::new(
                            field.span,
                            "arguments to #[construct_with] must be primitives",
                        ));
                    }
                }
                if inner_size % 8 != 0 {
                    return Err(Error::new(
                        field.span,
                        "types in #[construct_with] for vec must be add up to a multiple of 8 bits",
                    ));
                }
                inner_size /= 8; // bytes not bits
                *mutators = format!(
                    "{mutators}
                /// Set the value of the {name} field.
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                pub fn set_{name}(&mut self, vals: &Vec<{inner_ty_str}>) {{
                    use pnet_macros_support::packet::PrimitiveValues;
                    let _self = self;
                    {inner_mutators}
                    let mut additional_offset = 0;

                    for val in vals.into_iter() {{
                        let vals = val.to_primitive_values();

                        {set_args}

                        additional_offset += {inner_size};
                    }}
                }}
                ",
                    mutators = &mutators[..],
                    name = field.name,
                    inner_ty_str = inner_ty_str,
                    inner_mutators = inner_mutators,
                    //packet_length = field.packet_length.as_ref().unwrap(),
                    inner_size = inner_size,
                    set_args = set_args
                );
                *accessors = format!(
                    "{accessors}
                    /// Get the value of the {name} field
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                    pub fn get_{name}(&self) -> Vec<{inner_ty_str}> {{
                        let _self = self;
                        let length = {packet_length};
                        let vec_length = length.saturating_div({inner_size});
                        let mut vec = Vec::with_capacity(vec_length);

                        {inner_accessors}

                        let mut additional_offset = 0;

                        for vec_offset in 0..vec_length {{
                            vec.push({inner_ty_str}::new({get_args}));
                            additional_offset += {inner_size};
                        }}

                        vec
                    }}
                    ",
                    accessors = accessors,
                    name = field.name,
                    inner_ty_str = inner_ty_str,
                    inner_accessors = inner_accessors,
                    packet_length = field.packet_length.as_ref().unwrap(),
                    inner_size = inner_size,
                    get_args = &get_args[..get_args.len() - 2]
                );
                return Ok(());
            }
            *accessors = format!("{accessors}
                                /// Get the value of the {name} field (copies contents)
                                #[inline]
                                #[allow(trivial_numeric_casts)]
                                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                pub fn get_{name}(&self) -> Vec<{inner_ty_str}> {{
                                    use pnet_macros_support::packet::FromPacket;
                                    use core::cmp::min;
                                    let _self = self;
                                    let current_offset = {co};
                                    let end = min(current_offset + {packet_length}, _self.packet.len());

                                    {inner_ty_str}Iterable {{
                                        buf: &_self.packet[current_offset..end]
                                    }}.map(|packet| packet.from_packet())
                                      .collect::<Vec<_>>()
                                }}

                                /// Get the value of the {name} field as iterator
                                #[inline]
                                #[allow(trivial_numeric_casts)]
                                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                pub fn get_{name}_iter(&self) -> {inner_ty_str}Iterable {{
                                    use core::cmp::min;
                                    let _self = self;
                                    let current_offset = {co};
                                    let end = min(current_offset + {packet_length}, _self.packet.len());

                                    {inner_ty_str}Iterable {{
                                        buf: &_self.packet[current_offset..end]
                                    }}
                                }}
                                ",
                                 accessors = accessors,
                                 name = field.name,
                                 co = co,
                                 packet_length = field.packet_length.as_ref().unwrap(),
                                 inner_ty_str = inner_ty_str);
            *mutators = format!("{mutators}
                                /// Set the value of the {name} field (copies contents)
                                #[inline]
                                #[allow(trivial_numeric_casts)]
                                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                pub fn set_{name}(&mut self, vals: &[{inner_ty_str}]) {{
                                    use pnet_macros_support::packet::PacketSize;
                                    let _self = self;
                                    let mut current_offset = {co};
                                    let end = current_offset + {packet_length};
                                    for val in vals.into_iter() {{
                                        let mut packet = Mutable{inner_ty_str}Packet::new(&mut _self.packet[current_offset..]).unwrap();
                                        packet.populate(val);
                                        current_offset += packet.packet_size();
                                        assert!(current_offset <= end);
                                    }}
                                }}
                                ",
                                mutators = mutators,
                                name = field.name,
                                co = co,
                                packet_length = field.packet_length.as_ref().unwrap(),
                                inner_ty_str = inner_ty_str);
            Ok(())
        }
    }
}

/// Given a type in the form `u([0-9]+)(be|le)?`, return a tuple of it's size and endianness
///
/// If 1 <= size <= 8, Endianness will be Big.
fn parse_ty(ty: &str) -> Option<(usize, Endianness, EndiannessSpecified)> {
    let re = Regex::new(r"^u([0-9]+)(be|le|he)?$").unwrap();
    let iter = match re.captures_iter(ty).next() {
        Some(c) => c,
        None => return None,
    };
    if iter.len() == 3 || iter.len() == 2 {
        let size = iter.get(1).unwrap().as_str();
        let (endianness, has_end) = if let Some(e) = iter.get(2) {
            let e = e.as_str();
            if e == "be" {
                (Endianness::Big, EndiannessSpecified::Yes)
            } else if e == "he" {
                (Endianness::Host, EndiannessSpecified::Yes)
            } else {
                (Endianness::Little, EndiannessSpecified::Yes)
            }
        } else {
            (Endianness::Big, EndiannessSpecified::No)
        };

        if let Ok(sz) = size.parse() {
            Some((sz, endianness, has_end))
        } else {
            None
        }
    } else {
        None
    }
}

fn ty_to_string(ty: &syn::Type) -> String {
    // XXX this inserts extra spaces (ex: "Vec < u8 >")
    let s = quote!(#ty).to_string();
    s.replace(" < ", "<").replace(" > ", ">").replace(" >", ">")
}

#[test]
fn test_parse_ty() {
    assert_eq!(
        parse_ty("u8"),
        Some((8, Endianness::Big, EndiannessSpecified::No))
    );
    assert_eq!(
        parse_ty("u21be"),
        Some((21, Endianness::Big, EndiannessSpecified::Yes))
    );
    assert_eq!(
        parse_ty("u21le"),
        Some((21, Endianness::Little, EndiannessSpecified::Yes))
    );
    assert_eq!(
        parse_ty("u21he"),
        Some((21, Endianness::Host, EndiannessSpecified::Yes))
    );
    assert_eq!(
        parse_ty("u9"),
        Some((9, Endianness::Big, EndiannessSpecified::No))
    );
    assert_eq!(
        parse_ty("u16"),
        Some((16, Endianness::Big, EndiannessSpecified::No))
    );
    assert_eq!(parse_ty("uable"), None);
    assert_eq!(parse_ty("u21re"), None);
    assert_eq!(parse_ty("i21be"), None);
}

fn generate_sop_strings(operations: &[SetOperation]) -> String {
    let mut op_strings = String::new();
    for (idx, sop) in operations.iter().enumerate() {
        let pkt_replace = format!("_self.packet[co + {}]", idx);
        let val_replace = "val";
        let sop = sop
            .to_string()
            .replace("{packet}", &pkt_replace[..])
            .replace("{val}", val_replace);
        op_strings = op_strings + &sop[..] + ";\n";
    }

    op_strings
}

enum AccessorMutator {
    Accessor,
    Mutator,
}

fn generate_accessor_or_mutator_comment(name: &str, ty: &str, op_type: AccessorMutator) -> String {
    let get_or_set = match op_type {
        AccessorMutator::Accessor => "Get",
        AccessorMutator::Mutator => "Set",
    };
    if let Some((_, endianness, end_specified)) = parse_ty(ty) {
        if end_specified == EndiannessSpecified::Yes {
            let return_or_want = match op_type {
                AccessorMutator::Accessor => "accessor returns",
                AccessorMutator::Mutator => "mutator wants",
            };
            let endian_str = match endianness {
                Endianness::Big => "big-endian",
                Endianness::Little => "little-endian",
                Endianness::Host => "host-endian",
            };

            return format!(
                "/// {get_or_set} the {name} field. This field is always stored {endian}
                /// within the struct, but this {return_or_want} host order.",
                get_or_set = get_or_set,
                name = name,
                endian = endian_str,
                return_or_want = return_or_want
            );
        }
    }
    format!(
        "/// {get_or_set} the {name} field.",
        get_or_set = get_or_set,
        name = name
    )
}

/// Given the name of a field, and a set of operations required to set that field, return
/// the Rust code required to set the field
fn generate_mutator_str(
    name: &str,
    ty: &str,
    offset: &str,
    operations: &[SetOperation],
    inner: Option<&str>,
) -> String {
    let op_strings = generate_sop_strings(operations);

    let mutator = if let Some(struct_name) = inner {
        format!(
            "#[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
    fn set_{name}(_self: &mut {struct_name}, val: {ty}) {{
        let co = {co};
        {operations}
    }}",
            struct_name = struct_name,
            name = name,
            ty = ty,
            co = offset,
            operations = op_strings
        )
    } else {
        let comment = generate_accessor_or_mutator_comment(name, ty, AccessorMutator::Mutator);
        format!(
            "{comment}
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
    pub fn set_{name}(&mut self, val: {ty}) {{
        let _self = self;
        let co = {co};
        {operations}
    }}",
            comment = comment,
            name = name,
            ty = ty,
            co = offset,
            operations = op_strings
        )
    };

    mutator
}

fn generate_mutator_with_offset_str(
    name: &str,
    ty: &str,
    offset: &str,
    operations: &[SetOperation],
    inner: &str,
) -> String {
    let op_strings = generate_sop_strings(operations);

    format!(
        "#[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
    fn set_{name}(_self: &mut {struct_name}, val: {ty}, offset: usize) {{
        let co = {co} + offset;
        {operations}
    }}",
        struct_name = inner,
        name = name,
        ty = ty,
        co = offset,
        operations = op_strings
    )
}

/// Used to turn something like a u16be into
/// "let b0 = ((_self.packet[co + 0] as u16be) << 8) as u16be;
///  let b1 = ((_self.packet[co + 1] as u16be) as u16be;
///  b0 | b1"
fn generate_accessor_op_str(name: &str, ty: &str, operations: &[GetOperation]) -> String {
    fn build_return(max: usize) -> String {
        let mut ret = "".to_owned();
        for i in 0..max {
            ret = ret + &format!("b{} | ", i)[..];
        }
        let new_len = ret.len() - 3;
        ret.truncate(new_len);

        ret
    }

    let op_strings = if operations.len() == 1 {
        let replacement_str = format!("({}[co] as {})", name, ty);
        operations
            .first()
            .unwrap()
            .to_string()
            .replace("{}", &replacement_str[..])
    } else {
        let mut op_strings = "".to_owned();
        for (idx, operation) in operations.iter().enumerate() {
            let replacement_str = format!("({}[co + {}] as {})", name, idx, ty);
            let operation = operation.to_string().replace("{}", &replacement_str[..]);
            op_strings = op_strings + &format!("let b{} = ({}) as {};\n", idx, operation, ty)[..];
        }
        op_strings = op_strings + &format!("\n{}\n", build_return(operations.len()))[..];

        op_strings
    };

    op_strings
}

#[test]
fn test_generate_accessor_op_str() {
    {
        let ops = operations(0, 24).unwrap();
        let result = generate_accessor_op_str("test", "u24be", &ops);
        let expected = "let b0 = ((test[co + 0] as u24be) << 16) as u24be;\n\
                    let b1 = ((test[co + 1] as u24be) << 8) as u24be;\n\
                    let b2 = ((test[co + 2] as u24be)) as u24be;\n\n\
                    b0 | b1 | b2\n";

        assert_eq!(result, expected);
    }

    {
        let ops = operations(0, 16).unwrap();
        let result = generate_accessor_op_str("test", "u16be", &ops);
        let expected = "let b0 = ((test[co + 0] as u16be) << 8) as u16be;\n\
                    let b1 = ((test[co + 1] as u16be)) as u16be;\n\n\
                    b0 | b1\n";
        assert_eq!(result, expected);
    }

    {
        let ops = operations(0, 8).unwrap();
        let result = generate_accessor_op_str("test", "u8", &ops);
        let expected = "(test[co] as u8)";
        assert_eq!(result, expected);
    }
}

/// Given the name of a field, and a set of operations required to get the value of that field,
/// return the Rust code required to get the field.
#[inline]
fn generate_accessor_str(
    name: &str,
    ty: &str,
    offset: &str,
    operations: &[GetOperation],
    inner: Option<&str>,
) -> String {
    let op_strings = generate_accessor_op_str("_self.packet", ty, operations);

    let accessor = if let Some(struct_name) = inner {
        format!(
            "#[inline(always)]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
        fn get_{name}(_self: &{struct_name}) -> {ty} {{
            let co = {co};
            {operations}
        }}",
            struct_name = struct_name,
            name = name,
            ty = ty,
            co = offset,
            operations = op_strings
        )
    } else {
        let comment = generate_accessor_or_mutator_comment(name, ty, AccessorMutator::Accessor);
        format!(
            "{comment}
        #[inline]
        #[allow(trivial_numeric_casts, unused_parens)]
        #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
        pub fn get_{name}(&self) -> {ty} {{
            let _self = self;
            let co = {co};
            {operations}
        }}",
            comment = comment,
            name = name,
            ty = ty,
            co = offset,
            operations = op_strings
        )
    };

    accessor
}

#[inline]
fn generate_accessor_with_offset_str(
    name: &str,
    ty: &str,
    offset: &str,
    operations: &[GetOperation],
    inner: &str,
) -> String {
    let op_strings = generate_accessor_op_str("_self.packet", ty, operations);

    format!(
        "#[inline(always)]
    #[allow(trivial_numeric_casts, unused_parens)]
    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
    fn get_{name}(_self: &{struct_name}, offset: usize) -> {ty} {{
        let co = {co} + offset;
        {operations}
    }}",
        struct_name = inner,
        name = name,
        ty = ty,
        co = offset,
        operations = op_strings
    )
}

#[inline]
fn current_offset(bit_offset: usize, offset_fns: &[String]) -> String {
    let base_offset = bit_offset / 8;

    offset_fns
        .iter()
        .fold(base_offset.to_string(), |a, b| a + " + " + &b[..])
}

#[inline]
fn generate_get_fields(packet: &Packet) -> String {
    let mut gets = String::new();

    for field in &packet.fields {
        if field.is_payload {
            gets = gets
                + &format!(
                    "{field} : {{
                                                let payload = self.payload();
                                                let mut vec = Vec::with_capacity(payload.len());
                                                vec.extend_from_slice(payload);

                                                vec
                                            }},\n",
                    field = field.name
                )[..]
        } else {
            gets = gets + &format!("{field} : _self.get_{field}(),\n", field = field.name)[..]
        }
    }

    gets
}
