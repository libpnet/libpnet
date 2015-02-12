// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Linting and other functionality which requires type information

use rustc::lint::{LintPass, LintArray};

declare_lint! {
    PACKET_LINT,
    Forbid,
    "additional type checking for #[packet] structs and enums"
}

pub struct PacketPass;

impl LintPass for PacketPass {
    fn get_lints(&self) -> LintArray {
        lint_array!(PACKET_LINT)
    }
}
