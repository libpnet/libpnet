// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Implements the #[packet] decorator

use regex::Regex;
use std::rc::Rc;

use syntax::ast;
use syntax::tokenstream::Delimited;
use syntax::tokenstream::TokenTree::{self, Sequence, Token};
use syntax::codemap::Span;
use syntax::ext::base::{Annotatable, ExtCtxt};
use syntax::ext::quote::rt::ExtParseUtils;
use syntax::parse::token;
use syntax::print::pprust::{tts_to_string, ty_to_string};
use syntax::ptr::P;

use util::{Endianness, GetOperation, SetOperation, to_little_endian, operations, to_mutator};

/// Lower and upper bounds of a payload
/// Represented as strings since they may involve functions.
struct PayloadBounds {
    lower: String,
    upper: String,
}

#[derive(Clone, PartialEq)]
enum Type {
    /// Any of the u* types from pnet_macros::types::*
    Primitive(String, usize, Endianness),
    /// Any type of the form Vec<T>
    Vector(Box<Type>),
    /// Any type which isn't a primitive or a vector
    Misc(String)
}

#[derive(Clone)]
struct Field {
    name: String,
    span: Span,
    ty: Type,
    packet_length: Option<String>,
    struct_length: Option<String>,
    is_payload: bool,
    construct_with: Option<Vec<Type>>
}

#[derive(Clone)]
struct Packet {
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

fn make_type(ty_str: String, endianness_important: bool) -> Result<Type, String> {
    if let Some((size, endianness, spec)) = parse_ty(&ty_str[..]) {
        if !endianness_important || size <= 8 || spec == EndiannessSpecified::Yes {
            Ok(Type::Primitive(ty_str, size, endianness))
        } else {
            Err("endianness must be specified for types of size >= 8".to_owned())
        }
    } else if ty_str.starts_with("Vec<") {
        let ty = make_type(String::from(&ty_str[4..ty_str.len()-1]), endianness_important);
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

fn multiple_payload_error(ecx: &mut ExtCtxt, field_span: Span, payload_span: Span) {
    ecx.struct_span_err(field_span, "packet may not have multiple payloads")
        .span_note(payload_span, "first payload defined here")
        .emit();
}

fn make_packet(ecx: &mut ExtCtxt, span: Span, name: String, vd: &ast::VariantData) -> Option<Packet> {
    let mut payload_span = None;
    let mut fields = Vec::new();

    // FIXME This is an ugly hack to match the old behaviour
    let sfields = match *vd {
        ast::VariantData::Struct(ref fields, _) => {
            fields
        },
        ast::VariantData::Tuple(ref fields, _) => {
            for ref field in fields {
                if let None = field.ident {
                    ecx.span_err(field.span, "all fields in a packet must be named");
                    return None;
                }
            }
            return None;
        },
        _ => return None
    };

    for ref field in sfields {
        let field_name = match field.ident {
            Some(name) => name.to_string(),
            None => {
                panic!("This shouldn't happen");
            }
        };
        let mut is_payload = false;
        let mut packet_length = None;
        let mut struct_length = None;
        let mut construct_with = Vec::new();
        let mut seen = Vec::new();
        for attr in &field.attrs {
            let node = &attr.node.value.node;
            match *node {
                ast::MetaItemKind::Word(ref s) => {
                    seen.push(s.to_owned());
                    if &s[..] == "payload" {
                        if payload_span.is_some() {
                            multiple_payload_error(ecx, field.span, payload_span.unwrap());
                            return None;
                        }
                        is_payload = true;
                        payload_span = Some(field.span);
                    } else {
                        ecx.span_err(field.span, &format!("unknown attribute: {}", s)[..]);
                        return None;
                    }
                },
                ast::MetaItemKind::List(ref s, ref items) => {
                    seen.push(s.to_owned());
                    if &s[..] == "construct_with" {
                        if items.iter().len() == 0 {
                            ecx.span_err(field.span, "#[construct_with] must have at least one argument");
                            return None;
                        }
                        for ty in items.iter() {
                            if let ast::MetaItemKind::Word(ref s) = ty.node {
                                match make_type(s.to_string(), false) {
                                    Ok(ty) => construct_with.push(ty),
                                    Err(e) => {
                                        ecx.span_err(field.span, &e);
                                        return None;
                                    }
                                }
                            } else {
                                ecx.span_err(field.span, "#[construct_with] should be of the form #[construct_with(<types>)]");
                                return None;
                            }
                        }
                    } else {
                        ecx.span_err(field.span, &format!("unknown attribute: {}", s)[..]);
                        return None;
                    }
                },
                ast::MetaItemKind::NameValue(ref s, ref lit) => {
                    seen.push(s.to_owned());
                    match &s[..] {
                        "length_fn" => {
                            let node = &lit.node;
                            if let ast::LitKind::Str(ref s, _) = *node {
                                packet_length = Some(s.to_string() + "(&_self.to_immutable())");
                            } else {
                                ecx.span_err(field.span, "#[length_fn] should be used as #[length_fn = \"name_of_function\"]");
                                return None;
                            }
                        },
                        "length" => {
                            let node = &lit.node;
                            if let ast::LitKind::Str(ref s, _) = *node {
                                let field_names: Vec<String> = sfields.iter().filter_map(|field| {
                                    field.ident
                                        .map(|name| name.to_string())
                                        .and_then(|name| {
                                            if name == field_name {
                                                None
                                            } else {
                                                Some(name)
                                            }
                                        })
                                }).collect();
                                let tt_tokens = ecx.parse_tts(s.to_string());
                                let tokens_packet = parse_length_expr(ecx, &tt_tokens, &field_names);
                                let parsed = tts_to_string(&tokens_packet[..]);
                                packet_length = Some(parsed);
                            } else {
                                ecx.span_err(field.span, "#[length] should be used as #[length = \"field_name and/or arithmetic expression\"]");
                                return None;
                            }
                        },
                        _ => {
                            ecx.span_err(field.span, &format!("unknown attribute: {}", s)[..]);
                            return None;
                        }
                    }
                }
            }
        }
        let old_len = seen.len();
        seen.dedup();
        if seen.len() != old_len {
            ecx.span_err(field.span, "cannot have two attributes with the same name");
            return None;
        }

        let ty = match make_type(ty_to_string(&*field.ty), true) {
            Ok(ty) => ty,
            Err(e) => {
                ecx.span_err(field.span, &e);
                return None;
            }
        };

        match ty {
            Type::Vector(_) => {
                struct_length = Some(format!("_packet.{}.len()", field_name).to_owned());
                if !is_payload && packet_length.is_none() {
                    ecx.span_err(field.span,
                                 "variable length field must have #[length = \"\"] or #[length_fn = \"\"] attribute");
                    return None;
                }
            },
            Type::Misc(_) => {
                if construct_with.is_empty() {
                    ecx.span_err(field.span,
                                 "non-primitive field types must specify #[construct_with]");
                    return None;
                }
            },
            _ => {}
        }

        fields.push(Field {
            name: field_name,
            span: field.span,
            ty: ty,
            packet_length: packet_length,
            struct_length: struct_length,
            is_payload: is_payload,
            construct_with: Some(construct_with),
        });
    }

    if payload_span.is_none() {
        ecx.span_err(span, "#[packet]'s must contain a payload");
        return None;
    }

    Some(Packet {
        base_name: name,
        fields: fields,
    })

}

fn make_packets(ecx: &mut ExtCtxt, span: Span, item: &Annotatable) -> Option<Vec<Packet>> {
    if let Annotatable::Item(ref item) = *item {
        match item.node {
            ast::ItemKind::Enum(ref ed, ref _gs) => {
                if item.vis != ast::Visibility::Public {
                    ecx.span_err(item.span, "#[packet] enums must be public");
                    return None;
                }
                let mut vec = vec![];
                for ref variant in &ed.variants {
                    if variant.node.data.is_struct() {
                        let name = variant.node.name.to_string();
                        if let Some(packet) = make_packet(ecx, span, name, &variant.node.data) {
                            vec.push(packet);
                        } else {
                            return None;
                        }
                    } else {
                        ecx.span_err(variant.span, "");
                        return None;
                    }
                }

                Some(vec)
            },
            ast::ItemKind::Struct(ref sd, ref _gs) => {
                if item.vis != ast::Visibility::Public {
                    ecx.span_err(item.span, "#[packet] structs must be public");
                    return None;
                }
                let name = item.ident.to_string();
                if let Some(packet) = make_packet(ecx, span, name, sd) {
                    Some(vec![packet])
                } else {
                    None
                }
            },
            _ => {
                ecx.span_err(span, "#[packet] may only be used with enums and structs");

                None
            }
        }
    } else {
        ecx.span_err(span, "#[packet] may only be used with enums and structs");

        None
    }
}

//// Return the processed length expression for the packet
fn parse_length_expr(ecx: &mut ExtCtxt, tts: &[TokenTree], field_names: &[String])
                     -> Vec<TokenTree> {
    let error_msg = "Only field names, constants, integers, basic arithmetic expressions \
                     (+ - * / %) and parentheses are allowed in the \"length\" attribute";
    let tokens_packet = tts.iter().fold(Vec::new(), |mut acc_packet, tt_token| {
        match *tt_token {
            Token(span, token::Ident(name)) => {
                if name.to_string().chars().any(|c| c.is_lowercase()) {
                    if field_names.contains(&name.to_string()) {
                        let mut modified_packet_tokens = ecx.parse_tts(
                            format!("_self.get_{}() as usize", name).to_owned());
                        acc_packet.append(&mut modified_packet_tokens);
                    } else {
                        ecx.span_err(
                            span,
                            "Field name must be a member of the struct and not the field itself");
                    }
                }
                // Constants are only recongized if they are all uppercase
                else {
                    let mut modified_packet_tokens = ecx.parse_tts(
                        format!("{} as usize", name).to_owned());
                    acc_packet.append(&mut modified_packet_tokens);
                }
            },
            Token(_, token::ModSep) => {
                acc_packet.push(tt_token.clone());
            },
            Token(span, token::BinOp(binop)) => {
                match binop {
                    token::Plus | token::Minus | token::Star | token::Slash | token::Percent => {
                        acc_packet.push(tt_token.clone());
                    },
                    _ => {
                        ecx.span_err(span, error_msg);
                    }
                };
            },
            Token(_, token::Literal(token::Integer(_), None)) => {
                acc_packet.push(tt_token.clone());
            },
            Token(span, _) => {
                ecx.span_err(span, error_msg);
            },
            TokenTree::Delimited(span, ref delimited) => {
                let tts = parse_length_expr(ecx, &delimited.tts, &field_names);
                let tt_delimited = Delimited {
                    delim: delimited.delim,
                    open_span: delimited.open_span,
                    tts: tts,
                    close_span: delimited.close_span
                };
                acc_packet.push(TokenTree::Delimited(span, Rc::new(tt_delimited)));
            },
            Sequence(span, _) => {
                ecx.span_err(span, error_msg);
            }
        };
        acc_packet
    });

    tokens_packet
}


struct GenContext<'a, 'b : 'a, 'c> {
    ecx: &'a mut ExtCtxt<'b>,
    push: &'c mut FnMut(P<ast::Item>)
}

impl<'a, 'b, 'c> GenContext<'a, 'b, 'c> {
    fn push_item_from_string(&mut self, item: String) {
        (*self.push)(self.ecx.parse_item(item));
    }
}

pub fn generate_packet(ecx: &mut ExtCtxt,
                   span: Span,
                   _meta_item: &ast::MetaItem,
                   item: &Annotatable,
                   push: &mut FnMut(Annotatable)) {
    if let Some(packets) = make_packets(ecx, span, item) {
        let mut cx = GenContext {
            ecx: ecx,
            push: &mut |item| push(Annotatable::Item(item))
        };

        for packet in &packets {
            generate_packet_structs(&mut cx, &packet);

            if let Some((payload_bounds, packet_size)) = generate_packet_impls(&mut cx, &packet) {
                generate_packet_size_impls(&mut cx, &packet, &packet_size[..]);

                generate_packet_trait_impls(&mut cx, &packet, &payload_bounds);
                generate_iterables(&mut cx, &packet);
                generate_converters(&mut cx, &packet);
                generate_debug_impls(&mut cx, &packet);
            }
        }
    }
}

fn generate_packet_structs(cx: &mut GenContext, packet: &Packet) {
    for (name, mutable) in vec![(packet.packet_name(), ""),
                             (packet.packet_name_mut(), " mut")] {
        cx.push_item_from_string(format!("
            #[derive(PartialEq)]
            /// A structure enabling manipulation of on the wire packets
            pub struct {}<'p> {{
                packet: &'p{} [u8],
            }}", name, mutable));
    }
}

fn handle_misc_field(cx: &mut GenContext,
                     error: &mut bool,
                     field: &Field,
                     bit_offset: &mut usize,
                     offset_fns: &[String],
                     co: &mut String,
                     name: &str,
                     mutators: &mut String,
                     accessors: &mut String,
                     ty_str: &str) {
    let mut inner_accessors = String::new();
    let mut inner_mutators = String::new();
    let mut get_args = String::new();
    let mut set_args = String::new();
    for (i, arg) in field.construct_with.as_ref().unwrap().iter().enumerate() {
        if let Type::Primitive(ref ty_str, size, endianness) = *arg {
            let mut ops = operations(*bit_offset % 8, size).unwrap();

            if endianness == Endianness::Little {
                ops = to_little_endian(ops);
            }
            let arg_name = format!("arg{}", i);
            inner_accessors = inner_accessors +
                                &generate_accessor_str(&arg_name[..], &ty_str[..], &co[..],
                                                       &ops[..], Some(&name[..]))[..];
            inner_mutators = inner_mutators +
                                &generate_mutator_str(&arg_name[..], &ty_str[..],
                                                      &co[..], &to_mutator(&ops[..])[..],
                                                      Some(&name[..]))[..];
            get_args = format!("{}get_{}(&self), ", get_args, arg_name);
            set_args = format!("{}set_{}(_self, vals.{});\n", set_args, arg_name, i);
            *bit_offset += size;
            // Current offset needs to be recalculated for each arg
            *co = current_offset(*bit_offset, offset_fns);
        } else {
            cx.ecx.span_err(field.span, "arguments to #[construct_with] must be primitives");
            *error = true;
        }
    }
    *mutators = format!("{mutators}
                    /// Set the value of the {name} field
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                    pub fn set_{name}(&mut self, val: {ty_str}) {{
                        use pnet::packet::PrimitiveValues;
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
                    set_args = set_args);
    let ctor = if field.construct_with.is_some() {
        format!("{} {}::new({})", inner_accessors, ty_str, &get_args[..get_args.len() - 2])
    } else {
        format!("let current_offset = {};

                                {}::new(&_self.packet[current_offset..])", co, ty_str)
    };
    *accessors = format!("{accessors}
                        /// Get the value of the {name} field
                        #[inline]
                        #[allow(trivial_numeric_casts)]
                        #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                        pub fn get_{name}(&self) -> {ty_str} {{
                            {ctor}
                        }}
                        ", accessors = accessors, name = field.name, ty_str = ty_str, ctor = ctor);

}

fn handle_vec_primitive(cx: &mut GenContext,
                        error: &mut bool,
                        inner_ty_str: &str,
                        size: usize,
                        field: &Field,
                        accessors: &mut String,
                        mutators: &mut String,
                        co: &mut String) {
    if inner_ty_str == "u8" || (size % 8) == 0 {
        let ops = operations(0, size).unwrap();
        if !field.is_payload {
            let op_strings = generate_accessor_op_str("packet", inner_ty_str, &ops);
            *accessors = format!("{accessors}
                                    /// Get the value of the {name} field (copies contents)
                                    #[inline]
                                    #[allow(trivial_numeric_casts)]
                                    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                    pub fn get_{name}(&self) -> Vec<{inner_ty_str}> {{
                                        use std::cmp::min;
                                        let _self = self;
                                        let current_offset = {co};
                                        let pkt_len = self.packet.len();
                                        let end = min(current_offset + {packet_length}, pkt_len);

                                        let packet = &_self.packet[current_offset..end];
                                        let mut vec: Vec<{inner_ty_str}> = Vec::with_capacity(packet.len());
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
                                    size = size/8);
        }
        let check_len = if field.packet_length.is_some() {
            format!("let len = {packet_length};
                                             assert!(vals.len() <= len);",
                                             packet_length = field.packet_length.as_ref().unwrap())
        } else {
            String::new()
        };

        let copy_vals = if inner_ty_str == "u8" {
            // Efficient copy_nonoverlapping (memcpy)
            format!("
                                    // &mut and & can never overlap
                                    unsafe {{
                                        copy_nonoverlapping(vals[..].as_ptr(),
                                                            _self.packet[current_offset..].as_mut_ptr(),
                                                            vals.len())
                                    }}
                                ")
        } else {
            // e.g. Vec<u16> -> Vec<u8>
            let sop_strings = generate_sop_strings(&to_mutator(&ops));
            format!("
                                let mut co = current_offset;
                                for i in 0..vals.len() {{
                                    let val = vals[i];
                                    {sop}
                                    co += {size};
                                }}",
                                sop = sop_strings,
                                size = size/8)
        };

        *mutators = format!("{mutators}
                                /// Set the value of the {name} field (copies contents)
                                #[inline]
                                #[allow(trivial_numeric_casts)]
                                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                pub fn set_{name}(&mut self, vals: &[{inner_ty_str}]) {{
                                    use std::ptr::copy_nonoverlapping;
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
                                copy_vals = copy_vals);

    } else {

        cx.ecx.span_err(field.span, "unimplemented variable length field");
        *error = true;
    }
}

fn handle_vector_field(cx: &mut GenContext,
                       error: &mut bool,
                       field: &Field,
                       accessors: &mut String,
                       mutators: &mut String,
                       inner_ty: &Box<Type>,
                       co: &mut String)
{
    if !field.is_payload && !field.packet_length.is_some() {
        cx.ecx.span_err(field.span, "variable length field must have #[length_fn = \"\"] attribute");
        *error = true;
    }
    if !field.is_payload {
        *accessors = format!("{accessors}
                                /// Get the raw &[u8] value of the {name} field, without copying
                                #[inline]
                                #[allow(trivial_numeric_casts)]
                                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                pub fn get_{name}_raw(&self) -> &[u8] {{
                                    use std::cmp::min;
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
                                    use std::cmp::min;
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
            handle_vec_primitive(cx, error, inner_ty_str, _size, field, accessors, mutators, co)
        },
        Type::Vector(_) => {
            cx.ecx.span_err(field.span, "variable length fields may not contain vectors");
            *error = true;
        },
        Type::Misc(ref inner_ty_str) => {
            *accessors = format!("{accessors}
                                /// Get the value of the {name} field (copies contents)
                                #[inline]
                                #[allow(trivial_numeric_casts)]
                                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                                pub fn get_{name}(&self) -> Vec<{inner_ty_str}> {{
                                    use pnet::packet::FromPacket;
                                    use std::cmp::min;
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
                                    use pnet::packet::FromPacket;
                                    use std::cmp::min;
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
                                    use pnet::packet::PacketSize;
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
        }
    }
}

fn generate_packet_impl(cx: &mut GenContext, packet: &Packet, mutable: bool, name: String)
    -> Option<(PayloadBounds, String)>
{
    let mut bit_offset = 0;
    let mut offset_fns_packet = Vec::new();
    let mut offset_fns_struct = Vec::new();
    let mut accessors = "".to_owned();
    let mut mutators = "".to_owned();
    let mut error = false;
    let mut payload_bounds = None;
    for (idx, ref field) in packet.fields.iter().enumerate() {
        let mut co = current_offset(bit_offset, &offset_fns_packet[..]);

        if field.is_payload {
            let mut upper_bound_str = "".to_owned();
            if field.packet_length.is_some() {
                upper_bound_str = format!("{} + {}",
                co.clone(),
                field.packet_length.as_ref().unwrap());
            } else {
                if idx != packet.fields.len() - 1 {
                    cx.ecx.span_err(field.span,
                                    "#[payload] must specify a #[length_fn], unless it is the last field of a packet");
                    error = true;
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

                if endianness == Endianness::Little {
                    ops = to_little_endian(ops);
                }
                mutators = mutators + &generate_mutator_str(&field.name[..], &ty_str[..], &co[..],
                                                            &to_mutator(&ops[..])[..], None)[..];
                accessors = accessors + &generate_accessor_str(&field.name[..], &ty_str[..],
                                                               &co[..], &ops[..], None)[..];
                bit_offset += size;
            },
            Type::Vector(ref inner_ty) => {
                handle_vector_field(cx, &mut error, &field, &mut accessors, &mut mutators, inner_ty, &mut co)
            },
            Type::Misc(ref ty_str) => {
                handle_misc_field(cx, &mut error, &field, &mut bit_offset, &offset_fns_packet[..],
                                  &mut co, &name, &mut mutators, &mut accessors, &ty_str)
            }
        }
        if field.packet_length.is_some() {
            offset_fns_packet.push(field.packet_length.as_ref().unwrap().clone());
        }
        if field.struct_length.is_some() {
            offset_fns_struct.push(field.struct_length.as_ref().unwrap().clone());
        }
    }

    if error {
        return None;
    }

    fn generate_set_fields(packet: &Packet) -> String {
        let mut set_fields = String::new();
        for field in &packet.fields {
            match field.ty {
                Type::Vector(_) => {
                    set_fields = set_fields + &format!("_self.set_{field}(&packet.{field});\n",
                    field = field.name)[..];
                },
                _ => {
                    set_fields = set_fields + &format!("_self.set_{field}(packet.{field});\n",
                    field = field.name)[..];
                }
            }
        }

        set_fields
    }

    let populate = if mutable {
        let set_fields = generate_set_fields(&packet);
        let imm_name = packet.packet_name();
        format!("/// Populates a {name}Packet using a {name} structure
             #[inline]
             #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
             pub fn populate(&mut self, packet: &{name}) {{
                 let _self = self;
                 {set_fields}
             }}", name = &imm_name[..imm_name.len() - 6], set_fields = set_fields)
    } else {
        "".to_owned()
    };

    // If there are no variable length fields defined, then `_packet` is not used, hence
    // the leading underscore
    let packet_size_struct = format!(
           "/// The size (in bytes) of a {base_name} instance when converted into
            /// a byte-array
            #[inline]
            pub fn packet_size(_packet: &{base_name}) -> usize {{
                {struct_size}
            }}",
            base_name = packet.base_name,
            struct_size = current_offset(bit_offset, &offset_fns_struct[..]));

    let byte_size = if bit_offset % 8 == 0 {
        bit_offset / 8
    } else {
        (bit_offset / 8) + 1
    };

    cx.push_item_from_string(format!("impl<'a> {name}<'a> {{
        /// Constructs a new {name}. If the provided buffer is less than the minimum required
        /// packet size, this will return None.
        #[inline]
        pub fn new<'p>(packet: &'p {mut} [u8]) -> Option<{name}<'p>> {{
            if packet.len() >= {name}::minimum_packet_size() {{
                Some({name} {{ packet: packet }})
            }} else {{
                None
            }}
        }}

        /// Maps from a {name} to a {imm_name}
        #[inline]
        pub fn to_immutable<'p>(&'p self) -> {imm_name}<'p> {{
            match *self {{
                {name} {{ ref packet }} => {imm_name} {{ packet: packet }}
            }}
        }}

        /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
        /// of the fixed-size fields.
        #[inline]
        pub fn minimum_packet_size() -> usize {{
            {byte_size}
        }}

        {packet_size_struct}

        {populate}

        {accessors}

        {mutators}
    }}", name = name,
    imm_name = packet.packet_name(),
    mut = if mutable { "mut" } else { "" },
    byte_size = byte_size,
    accessors = accessors,
    mutators = if mutable { &mutators[..] } else { "" },
    populate = populate,
    packet_size_struct = packet_size_struct
        ));

    Some((payload_bounds.unwrap(), current_offset(bit_offset, &offset_fns_packet[..])))
}


fn generate_packet_impls(cx: &mut GenContext, packet: &Packet) -> Option<(PayloadBounds, String)> {
    let mut ret = None;
    for (mutable, name) in vec![(false, packet.packet_name()),
                                (true, packet.packet_name_mut())] {
        ret = generate_packet_impl(cx, packet, mutable, name);
    }

    ret
}

fn generate_packet_size_impls(cx: &mut GenContext, packet: &Packet, size: &str) {
    for name in &[packet.packet_name(), packet.packet_name_mut()] {
        cx.push_item_from_string(format!("
            impl<'a> ::pnet::packet::PacketSize for {name}<'a> {{
                #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
                fn packet_size(&self) -> usize {{
                    let _self = self;
                    {size}
                }}
            }}
        ", name = name, size = size));
    }
}

fn generate_packet_trait_impls(cx: &mut GenContext, packet: &Packet, payload_bounds: &PayloadBounds) {
    for (name, mutable, u_mut, mut_) in vec![
        (packet.packet_name_mut(), "Mutable", "_mut", "mut"),
        (packet.packet_name_mut(), "", "", ""),
        (packet.packet_name(), "", "", "")
    ] {
        let mut pre = "".to_owned();
        let mut start = "".to_owned();
        let mut end = "".to_owned();
        if !payload_bounds.lower.is_empty() {
            pre = pre + &format!("let start = {};", payload_bounds.lower)[..];
            start = "start".to_owned();
        }
        if !payload_bounds.upper.is_empty() {
            pre = pre + &format!("let end = {};", payload_bounds.upper)[..];
            end = "end".to_owned();
        }
        cx.push_item_from_string(format!("impl<'a> ::pnet::packet::{mutable}Packet for {name}<'a> {{
            #[inline]
            fn packet{u_mut}<'p>(&'p {mut_} self) -> &'p {mut_} [u8] {{ &{mut_} self.packet[..] }}

            #[inline]
            #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
            fn payload{u_mut}<'p>(&'p {mut_} self) -> &'p {mut_} [u8] {{
                let _self = self;
                {pre}
                &{mut_} _self.packet[{start}..{end}]
            }}
        }}", name = name,
             start = start,
             end = end,
             pre = pre,
             mutable = mutable,
             u_mut = u_mut,
             mut_ = mut_));
    }
}

fn generate_iterables(cx: &mut GenContext, packet: &Packet) {
    let name = &packet.base_name;

    cx.push_item_from_string(format!("
    /// Used to iterate over a slice of `{name}Packet`s
    pub struct {name}Iterable<'a> {{
        buf: &'a [u8],
    }}
    ", name = name));

    cx.push_item_from_string(format!("
    impl<'a> Iterator for {name}Iterable<'a> {{
        type Item = {name}Packet<'a>;

        fn next(&mut self) -> Option<{name}Packet<'a>> {{
            use pnet::packet::PacketSize;
            use std::cmp::min;
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
    ", name = name));
}

fn generate_converters(cx: &mut GenContext, packet: &Packet) {
    let get_fields = generate_get_fields(packet);

    for name in &[packet.packet_name(), packet.packet_name_mut()] {
        cx.push_item_from_string(format!("
        impl<'p> ::pnet::packet::FromPacket for {packet}<'p> {{
            type T = {name};
            #[inline]
            fn from_packet(&self) -> {name} {{
                use pnet::packet::Packet;
                let _self = self;
                {name} {{
                    {get_fields}
                }}
            }}
        }}", packet = name, name = packet.base_name, get_fields = get_fields));
    }
}

fn generate_debug_impls(cx: &mut GenContext, packet: &Packet) {

    let mut field_fmt_str = String::new();
    let mut get_fields = String::new();

    for field in &packet.fields {
        if !field.is_payload {
            field_fmt_str = format!("{}{} : {{:?}}, ", field_fmt_str, field.name);
            get_fields = format!("{}, _self.get_{}()", get_fields, field.name);
        }
    }

    for packet in &[packet.packet_name(), packet.packet_name_mut()] {
        cx.push_item_from_string(format!("
        impl<'p> ::std::fmt::Debug for {packet}<'p> {{
            #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
            fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {{
                let _self = self;
                write!(fmt,
                       \"{packet} {{{{ {field_fmt_str} }}}}\"
                       {get_fields}
                )
            }}
        }}", packet = packet, field_fmt_str = field_fmt_str, get_fields = get_fields));
    }
}

#[derive(Debug, PartialEq, Eq)]
enum EndiannessSpecified {
    No,
    Yes
}

/// Given a type in the form `u([0-9]+)(be|le)?`, return a tuple of it's size and endianness
///
/// If 1 <= size <= 8, Endianness will be Big.
fn parse_ty(ty: &str) -> Option<(usize, Endianness, EndiannessSpecified)> {
    let re = Regex::new(r"^u([0-9]+)(be|le)?$").unwrap();
    let iter = match re.captures_iter(ty).next() {
        Some(c) => c,
        None => return None,
    };

    if iter.len() == 3 || iter.len() == 2 {
        let size = iter.at(1).unwrap();
        let (endianness, has_end) = if let Some(e) = iter.at(2) {
            if e == "be" {
                (Endianness::Big, EndiannessSpecified::Yes)
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

#[test]
fn test_parse_ty() {
    assert_eq!(parse_ty("u8"), Some((8, Endianness::Big, EndiannessSpecified::No)));
    assert_eq!(parse_ty("u21be"), Some((21, Endianness::Big, EndiannessSpecified::Yes)));
    assert_eq!(parse_ty("u21le"), Some((21, Endianness::Little, EndiannessSpecified::Yes)));
    assert_eq!(parse_ty("u9"), Some((9, Endianness::Big, EndiannessSpecified::No)));
    assert_eq!(parse_ty("u16"), Some((16, Endianness::Big, EndiannessSpecified::No)));
    assert_eq!(parse_ty("uable"), None);
    assert_eq!(parse_ty("u21re"), None);
    assert_eq!(parse_ty("i21be"), None);
}

fn generate_sop_strings(operations: &[SetOperation]) -> String {
    let mut op_strings = String::new();
    for (idx, sop) in operations.iter().enumerate() {
        let pkt_replace = format!("_self.packet[co + {}]", idx);
        let val_replace = "val";
        let sop = sop.to_string().replace("{packet}", &pkt_replace[..])
                                 .replace("{val}", val_replace);
        op_strings = op_strings + &sop[..] + ";\n";
    }

    op_strings
}

/// Given the name of a field, and a set of operations required to set that field, return
/// the Rust code required to set the field
fn generate_mutator_str(name: &str,
                        ty: &str,
                        offset: &str,
                        operations: &[SetOperation],
                        inner: Option<&str>) -> String {
    let op_strings = generate_sop_strings(operations);

    let mutator = if let Some(struct_name) = inner {
        format!("#[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
    fn set_{name}(_self: &mut {struct_name}, val: {ty}) {{
        let co = {co};
        {operations}
    }}", struct_name = struct_name, name = name, ty = ty, co = offset, operations = op_strings)
    } else {
        format!("/// Set the {name} field
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
    pub fn set_{name}(&mut self, val: {ty}) {{
        let _self = self;
        let co = {co};
        {operations}
    }}", name = name, ty = ty, co = offset, operations = op_strings)
    };

    mutator
}

/// Used to turn something like a u16be into
/// "let b0 = ((_self.packet[co + 0] as u16be) << 8) as u16be;
///  let b1 = ((_self.packet[co + 1] as u16be) as u16be;
///  b0 | b1"
fn generate_accessor_op_str(name: &str,
                            ty: &str,
                            operations: &[GetOperation]) -> String
{

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
        operations.first().unwrap().to_string().replace("{}", &replacement_str[..])
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
fn generate_accessor_str(name: &str,
                         ty: &str,
                         offset: &str,
                         operations: &[GetOperation],
                         inner: Option<&str>)
    -> String
{

    let op_strings = generate_accessor_op_str("_self.packet", ty, operations);

    let accessor = if let Some(struct_name) = inner {
        format!("#[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
        fn get_{name}(_self: &{struct_name}) -> {ty} {{
            let co = {co};
            {operations}
        }}", struct_name = struct_name, name = name, ty = ty, co = offset, operations = op_strings)
    } else {
        format!("/// Get the {name} field
        #[inline]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = \"clippy\", allow(used_underscore_binding))]
        pub fn get_{name}(&self) -> {ty} {{
            let _self = self;
            let co = {co};
            {operations}
        }}", name = name, ty = ty, co = offset, operations = op_strings)
    };

    accessor
}

fn current_offset(bit_offset: usize, offset_fns: &[String]) -> String {
    let base_offset = bit_offset / 8;

    offset_fns.iter().fold(base_offset.to_string(), |a, b| {
        a + " + " + &b[..]
    })
}

fn generate_get_fields(packet: &Packet) -> String {
    let mut gets = String::new();

    for field in &packet.fields {
        if field.is_payload {
            gets = gets + &format!("{field} : {{
                                                let payload = self.payload();
                                                let mut vec = Vec::with_capacity(payload.len());
                                                vec.extend_from_slice(payload);

                                                vec
                                            }},\n", field = field.name)[..]
        } else {
            gets = gets + &format!("{field} : _self.get_{field}(),\n", field = field.name)[..]
        }
    }

    gets
}


#[cfg(test)]
mod tests {
    use syntax::ast::CrateConfig;
    use syntax::ext::base::ExtCtxt;
    use syntax::ext::expand::ExpansionConfig;
    use syntax::ext::quote::rt::ExtParseUtils;
    use syntax::parse::ParseSess;
    use syntax::print::pprust::tts_to_string;

    fn assert_parse_length_expr(expr: &str, field_names: &[&str], expected: &str) {
        let sess = ParseSess::new();
        let mut feature_gated_cfgs = Vec::new();
        let mut ecx = ExtCtxt::new(&sess,
                                   CrateConfig::default(),
                                   ExpansionConfig::default("parse_length_expr".to_owned()),
                                   &mut feature_gated_cfgs);
        let expr_tokens = ecx.parse_tts(expr.to_owned());
        let field_names_vec: Vec<String> = field_names.iter()
                                                      .map(|field_name| (*field_name).to_owned())
                                                      .collect();
        let parsed = super::parse_length_expr(&mut ecx, &expr_tokens, &field_names_vec);
        let expected_tokens = ecx.parse_tts(expected.to_owned());
        assert_eq!(tts_to_string(&parsed), tts_to_string(&expected_tokens));
    }

    #[test]
    fn test_parse_expr_key() {
        assert_parse_length_expr("key", &["key"], "_self.get_key() as usize");
        assert_parse_length_expr("another_key", &["another_key"],
                                 "_self.get_another_key() as usize");
        assert_parse_length_expr("get_something", &["get_something"],
                                 "_self.get_get_something() as usize");
    }

    #[test]
    fn test_parse_expr_numbers() {
        assert_parse_length_expr("3", &[], "3");
        assert_parse_length_expr("1 + 2", &[], "1 + 2");
        assert_parse_length_expr("3 - 4", &[], "3 - 4");
        assert_parse_length_expr("5 * 6", &[], "5 * 6");
        assert_parse_length_expr("7 / 8", &[], "7 / 8");
        assert_parse_length_expr("9 % 10", &[], "9 % 10");
        assert_parse_length_expr("5 * 4 + 1 % 2 - 6 / 9", &[], "5 * 4 + 1 % 2 - 6 / 9");
        assert_parse_length_expr("5*4+1%2-6/9", &[], "5*4+1%2-6/9");
        assert_parse_length_expr("5* 4+1%   2-6/ 9", &[], "5* 4+1%   2-6/ 9");
    }

    #[test]
    fn test_parse_expr_key_and_numbers() {
        assert_parse_length_expr("key + 4", &["key"], "_self.get_key() as usize + 4");
        assert_parse_length_expr("another_key - 7 + 8 * 2 / 1 % 2", &["another_key"],
                                 "_self.get_another_key() as usize - 7 + 8 * 2 / 1 % 2");
        assert_parse_length_expr("2 * key - 4", &["key"], "2 * _self.get_key() as usize - 4");
    }

    #[test]
    fn test_parse_expr_parentheses() {
        assert_parse_length_expr("()", &[], "()");
        assert_parse_length_expr("(key)", &["key"], "(_self.get_key() as usize)");
        assert_parse_length_expr("(key + 5)", &["key"], "(_self.get_key() as usize + 5)");
        assert_parse_length_expr(
            "key + 5 * (10 - another_key)", &["key", "another_key"],
            "_self.get_key() as usize + 5 * (10 - _self.get_another_key() as usize)");
        assert_parse_length_expr("4 + 2 / (3 * (7 - 5))", &[], "4 + 2 / (3 * (7 - 5))");
    }

    #[test]
    fn test_parse_expr_constants() {
        assert_parse_length_expr("CONSTANT", &[], "CONSTANT as usize");
        assert_parse_length_expr("std::u32::MIN", &[], "std::u32::MIN as usize");
        assert_parse_length_expr("key * (4 + std::u32::MIN)", &["key"],
                                 "_self.get_key() as usize * (4 + std::u32::MIN as usize)");
    }
}
