// Copyright (c) 2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
#![feature(plugin_registrar, rustc_private)]

extern crate pnet_macros;
extern crate rustc_plugin;

#[plugin_registrar]
pub fn plugin_registrar(registry: &mut rustc_plugin::Registry) {
    pnet_macros::register(registry);
}

