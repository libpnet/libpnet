// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Miscellaneous utilities for low level networking

#![allow(missing_docs)]

extern crate pcapng;
use std::fs::{File};
use std::path::{PathBuf};


const CAPTURE_DIR: &'static str = "./test_data/";
const CAPTURE_EXT: &'static str = "pcapng";


fn get_capture_file(capture_name: &str) -> File {
    let mut path: PathBuf = PathBuf::from(CAPTURE_DIR);
    path.push(capture_name);
    path.set_extension(CAPTURE_EXT);
    File::open(&path).unwrap()
}


pub fn read_capture(capture_name: &str) -> Vec<Vec<u8>> {
    let mut file_handler: File = get_capture_file(capture_name);
    let mut reader = pcapng::SimpleReader::new(&mut file_handler);
    let mut packets: Vec<Vec<u8>> = vec![];
    for (_, enhanced_packet) in reader.packets() {
        packets.push(enhanced_packet.data);
    }
    packets
}
