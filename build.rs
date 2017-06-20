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
    extern crate pnet_macros;
    extern crate syntex;
    extern crate glob;
    
    use std::env;
    use std::path::Path;
    
    pub fn expand() {
        // globbing for files to pre-process:
        let pattern = "./src/packet/**/*.rs.in";
        for entry in glob::glob( pattern ).expect("Failed to read glob pattern") {
            if let Ok(path) = entry {
                let src     = Path::new( path.to_str().expect("Invalid src Specified.") );
                let out_dir = env::var_os( "OUT_DIR" ).expect("Invalid OUT_DIR.");
                let file    = Path::new( path.file_stem().expect("Invalid file_stem.") );
                let dst     = Path::new( &out_dir ).join(file);
                let mut registry = syntex::Registry::new();
                pnet_macros::register(&mut registry);
                registry.expand("", &src, &dst).unwrap();
            }
        }
    }
}

#[cfg(not(feature = "with-syntex"))]
mod macros {
    pub fn expand() {}
}

fn main() {
    macros::expand();
    print_link_search_path();
}
