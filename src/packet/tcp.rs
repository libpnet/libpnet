// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TCP packet abstraction

#[cfg(feature = "with-syntex")]
include!(concat!(env!("OUT_DIR"), "/tcp.rs"));

#[cfg(not(feature = "with-syntex"))]
include!("tcp.rs.in");
