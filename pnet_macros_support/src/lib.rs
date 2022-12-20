// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support library for `libpnet_macros`.
//!
//! This exists to remove the need for the plugin_as_library feature, and allow for static linking.

#![deny(missing_docs)]
#![no_std]

extern crate pnet_base;

pub mod packet;
pub mod types;
