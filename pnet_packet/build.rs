// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod macros {
    extern crate glob;
    extern crate pnet_macros;
    extern crate syntex;

    use std::env;
    use std::path::Path;

    pub fn expand() {
        // globbing for files to pre-process:
        let pattern = "./src/**/*.rs.in";
        for entry in glob::glob(pattern).expect("Failed to read glob pattern") {
            if let Ok(path) = entry {
                let src = Path::new(path.to_str().expect("Invalid src Specified."));
                let out_dir = env::var_os("OUT_DIR").expect("Invalid OUT_DIR.");
                let file = Path::new(path.file_stem().expect("Invalid file_stem."));
                let dst = Path::new(&out_dir).join(file);
                let mut registry = syntex::Registry::new();
                pnet_macros::register(&mut registry);
                registry.expand("", &src, &dst).unwrap();
            }
        }
    }
}

fn main() {
    macros::expand();
}
