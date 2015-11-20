// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Provides type aliases for various primitive integer types
//!
//! These types are aliased to the next largest of [`u8`, `u16`, `u32`, `u64`], and purely serve as
//! hints for the `#[packet]` macro to enable the generation of the correct bit manipulations to
//! get the value out of a packet.
//!
//! They should NOT be used outside of data types marked as `#[packet]`.
//!
//! All aliases for types larger than `u8` contain a `be` or `le` suffix. These specify whether the
//! value is big or little endian, respectively. When using `set_*()` and `get_*()` methods, host
//! endianness should be used - the methods will convert as appropriate.

#![allow(non_camel_case_types)]

// TODO signed equivalents?

/// Represents an unsigned, 1-bit integer
pub type u1 = u8;

/// Represents an unsigned, 2-bit integer
pub type u2 = u8;

/// Represents an unsigned, 3-bit integer
pub type u3 = u8;

/// Represents an unsigned, 4-bit integer
pub type u4 = u8;

/// Represents an unsigned, 5-bit integer
pub type u5 = u8;

/// Represents an unsigned, 6-bit integer
pub type u6 = u8;

/// Represents an unsigned, 7-bit integer
pub type u7 = u8;


/// Represents an unsigned, 9-bit, big endian integer
pub type u9be = u16;

/// Represents an unsigned, 10-bit, big endian integer
pub type u10be = u16;

/// Represents an unsigned, 11-bit, big endian integer
pub type u11be = u16;

/// Represents an unsigned, 12-bit, big endian integer
pub type u12be = u16;

/// Represents an unsigned, 13-bit, big endian integer
pub type u13be = u16;

/// Represents an unsigned, 14-bit, big endian integer
pub type u14be = u16;

/// Represents an unsigned, 15-bit, big endian integer
pub type u15be = u16;

/// Represents an unsigned, 16-bit, big endian integer
pub type u16be = u16;

/// Represents an unsigned, 17-bit, big endian integer
pub type u17be = u32;

/// Represents an unsigned, 18-bit, big endian integer
pub type u18be = u32;

/// Represents an unsigned, 19-bit, big endian integer
pub type u19be = u32;

/// Represents an unsigned, 20-bit, big endian integer
pub type u20be = u32;

/// Represents an unsigned, 21-bit, big endian integer
pub type u21be = u32;

/// Represents an unsigned, 22-bit, big endian integer
pub type u22be = u32;

/// Represents an unsigned, 23-bit, big endian integer
pub type u23be = u32;

/// Represents an unsigned, 24-bit, big endian integer
pub type u24be = u32;

/// Represents an unsigned, 25-bit, big endian integer
pub type u25be = u32;

/// Represents an unsigned, 26-bit, big endian integer
pub type u26be = u32;

/// Represents an unsigned, 27-bit, big endian integer
pub type u27be = u32;

/// Represents an unsigned, 28-bit, big endian integer
pub type u28be = u32;

/// Represents an unsigned, 29-bit, big endian integer
pub type u29be = u32;

/// Represents an unsigned, 30-bit, big endian integer
pub type u30be = u32;

/// Represents an unsigned, 31-bit, big endian integer
pub type u31be = u32;

/// Represents an unsigned, 32-bit, big endian integer
pub type u32be = u32;

/// Represents an unsigned, 33-bit, big endian integer
pub type u33be = u64;

/// Represents an unsigned, 34-bit, big endian integer
pub type u34be = u64;

/// Represents an unsigned, 35-bit, big endian integer
pub type u35be = u64;

/// Represents an unsigned, 36-bit, big endian integer
pub type u36be = u64;

/// Represents an unsigned, 37-bit, big endian integer
pub type u37be = u64;

/// Represents an unsigned, 38-bit, big endian integer
pub type u38be = u64;

/// Represents an unsigned, 39-bit, big endian integer
pub type u39be = u64;

/// Represents an unsigned, 40-bit, big endian integer
pub type u40be = u64;

/// Represents an unsigned, 41-bit, big endian integer
pub type u41be = u64;

/// Represents an unsigned, 42-bit, big endian integer
pub type u42be = u64;

/// Represents an unsigned, 43-bit, big endian integer
pub type u43be = u64;

/// Represents an unsigned, 44-bit, big endian integer
pub type u44be = u64;

/// Represents an unsigned, 45-bit, big endian integer
pub type u45be = u64;

/// Represents an unsigned, 46-bit, big endian integer
pub type u46be = u64;

/// Represents an unsigned, 47-bit, big endian integer
pub type u47be = u64;

/// Represents an unsigned, 48-bit, big endian integer
pub type u48be = u64;

/// Represents an unsigned, 49-bit, big endian integer
pub type u49be = u64;

/// Represents an unsigned, 50-bit, big endian integer
pub type u50be = u64;

/// Represents an unsigned, 51-bit, big endian integer
pub type u51be = u64;

/// Represents an unsigned, 52-bit, big endian integer
pub type u52be = u64;

/// Represents an unsigned, 53-bit, big endian integer
pub type u53be = u64;

/// Represents an unsigned, 54-bit, big endian integer
pub type u54be = u64;

/// Represents an unsigned, 55-bit, big endian integer
pub type u55be = u64;

/// Represents an unsigned, 56-bit, big endian integer
pub type u56be = u64;

/// Represents an unsigned, 57-bit, big endian integer
pub type u57be = u64;

/// Represents an unsigned, 58-bit, big endian integer
pub type u58be = u64;

/// Represents an unsigned, 59-bit, big endian integer
pub type u59be = u64;

/// Represents an unsigned, 60-bit, big endian integer
pub type u60be = u64;

/// Represents an unsigned, 61-bit, big endian integer
pub type u61be = u64;

/// Represents an unsigned, 62-bit, big endian integer
pub type u62be = u64;

/// Represents an unsigned, 63-bit, big endian integer
pub type u63be = u64;

/// Represents an unsigned, 64-bit, big endian integer
pub type u64be = u64;


/// Represents an unsigned, 9-bit, little endian integer
pub type u9le = u16;

/// Represents an unsigned, 10-bit, little endian integer
pub type u10le = u16;

/// Represents an unsigned, 11-bit, little endian integer
pub type u11le = u16;

/// Represents an unsigned, 12-bit, little endian integer
pub type u12le = u16;

/// Represents an unsigned, 13-bit, little endian integer
pub type u13le = u16;

/// Represents an unsigned, 14-bit, little endian integer
pub type u14le = u16;

/// Represents an unsigned, 15-bit, little endian integer
pub type u15le = u16;

/// Represents an unsigned, 16-bit, little endian integer
pub type u16le = u16;

/// Represents an unsigned, 17-bit, little endian integer
pub type u17le = u32;

/// Represents an unsigned, 18-bit, little endian integer
pub type u18le = u32;

/// Represents an unsigned, 19-bit, little endian integer
pub type u19le = u32;

/// Represents an unsigned, 20-bit, little endian integer
pub type u20le = u32;

/// Represents an unsigned, 21-bit, little endian integer
pub type u21le = u32;

/// Represents an unsigned, 22-bit, little endian integer
pub type u22le = u32;

/// Represents an unsigned, 23-bit, little endian integer
pub type u23le = u32;

/// Represents an unsigned, 24-bit, little endian integer
pub type u24le = u32;

/// Represents an unsigned, 25-bit, little endian integer
pub type u25le = u32;

/// Represents an unsigned, 26-bit, little endian integer
pub type u26le = u32;

/// Represents an unsigned, 27-bit, little endian integer
pub type u27le = u32;

/// Represents an unsigned, 28-bit, little endian integer
pub type u28le = u32;

/// Represents an unsigned, 29-bit, little endian integer
pub type u29le = u32;

/// Represents an unsigned, 30-bit, little endian integer
pub type u30le = u32;

/// Represents an unsigned, 31-bit, little endian integer
pub type u31le = u32;

/// Represents an unsigned, 32-bit, little endian integer
pub type u32le = u32;

/// Represents an unsigned, 33-bit, little endian integer
pub type u33le = u64;

/// Represents an unsigned, 34-bit, little endian integer
pub type u34le = u64;

/// Represents an unsigned, 35-bit, little endian integer
pub type u35le = u64;

/// Represents an unsigned, 36-bit, little endian integer
pub type u36le = u64;

/// Represents an unsigned, 37-bit, little endian integer
pub type u37le = u64;

/// Represents an unsigned, 38-bit, little endian integer
pub type u38le = u64;

/// Represents an unsigned, 39-bit, little endian integer
pub type u39le = u64;

/// Represents an unsigned, 40-bit, little endian integer
pub type u40le = u64;

/// Represents an unsigned, 41-bit, little endian integer
pub type u41le = u64;

/// Represents an unsigned, 42-bit, little endian integer
pub type u42le = u64;

/// Represents an unsigned, 43-bit, little endian integer
pub type u43le = u64;

/// Represents an unsigned, 44-bit, little endian integer
pub type u44le = u64;

/// Represents an unsigned, 45-bit, little endian integer
pub type u45le = u64;

/// Represents an unsigned, 46-bit, little endian integer
pub type u46le = u64;

/// Represents an unsigned, 47-bit, little endian integer
pub type u47le = u64;

/// Represents an unsigned, 48-bit, little endian integer
pub type u48le = u64;

/// Represents an unsigned, 49-bit, little endian integer
pub type u49le = u64;

/// Represents an unsigned, 50-bit, little endian integer
pub type u50le = u64;

/// Represents an unsigned, 51-bit, little endian integer
pub type u51le = u64;

/// Represents an unsigned, 52-bit, little endian integer
pub type u52le = u64;

/// Represents an unsigned, 53-bit, little endian integer
pub type u53le = u64;

/// Represents an unsigned, 54-bit, little endian integer
pub type u54le = u64;

/// Represents an unsigned, 55-bit, little endian integer
pub type u55le = u64;

/// Represents an unsigned, 56-bit, little endian integer
pub type u56le = u64;

/// Represents an unsigned, 57-bit, little endian integer
pub type u57le = u64;

/// Represents an unsigned, 58-bit, little endian integer
pub type u58le = u64;

/// Represents an unsigned, 59-bit, little endian integer
pub type u59le = u64;

/// Represents an unsigned, 60-bit, little endian integer
pub type u60le = u64;

/// Represents an unsigned, 61-bit, little endian integer
pub type u61le = u64;

/// Represents an unsigned, 62-bit, little endian integer
pub type u62le = u64;

/// Represents an unsigned, 63-bit, little endian integer
pub type u63le = u64;

/// Represents an unsigned, 64-bit, little endian integer
pub type u64le = u64;
