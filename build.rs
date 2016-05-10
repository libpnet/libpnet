// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(windows)]
fn print_link_search_path() {
    use std::env;

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}/lib", manifest_dir);
}

#[cfg(not(windows))]
fn print_link_search_path() {}

#[cfg(feature = "with-syntex")]
mod macros {
    extern crate syntex;
    extern crate pnet_macros;

    use std::env;
    use std::path::Path;

    const FILES: &'static [&'static str] = &[
        "ethernet.rs",
        "ipv4.rs",
        "ipv6.rs",
        "udp.rs",
        "tcp.rs",
    ];

    pub fn expand() {
        let out_dir = env::var_os("OUT_DIR").unwrap();

        for file in FILES {
            let src_file = format!("src/packet/{}.in", file);
            let src = Path::new(&src_file);
            let dst = Path::new(&out_dir).join(file);

            let mut registry = syntex::Registry::new();
            pnet_macros::register(&mut registry);

            registry.expand("", &src, &dst).unwrap();
        }
    }
}

#[cfg(not(feature = "with-syntex"))]
mod macros {
    pub fn expand() {
    }
}

fn main() {
    macros::expand();
    print_link_search_path();
}
