Using `#[packet]` in Your Own Project
=====================================

The libpnet library provides a few macros to reduce the boilerplate involved in
implementing new protocols. Unfortunately, with the current state of Rust macro
support, these aren't as easy to use in your own project as the rest of the
library is.

This document is a brief guide to getting a Rust package set up to use the
`syntex`-based `pnet_macros` crate in your own crates. It's currently only been
tested in the context of building an executable rather than a library, but it
should be fairly easily adaptable.

Setting Up `Cargo.toml`
-----------------------

In order to use `syntex`, you need to set up your package to use a non-standard
build script. You will provide a build script that invokes the `syntex`
pre-processor to do macro expansion on the protocol implementation source files.

Here's an example `Cargo.toml` file that describes the necessary build script
and dependencies:

```toml

[package]
name = "my_pnet_package"
version = "0.1.0"
authors = ["My Name <my.email@mydomain.com>"]
build = "build.rs"
[build-dependencies]
syntex = "X" # where X is the version of syntex used in pnet_macros/Cargo.toml
pnet_macros = "*"
[dependencies]
pnet = "*"
pnet_macros_support = "*"

```

First, note the `build = "build.rs"` line in the `[package]` section. This gives
the filename of the custom build script that `cargo` will invoke for you when
you run `cargo build`. The filename is relative to the package root directory,
so if you follow the example, you'll need to create a `build.rs` file in the
same directory as your `Cargo.toml` file.

Next, you'll notice the `[build-dependencies]` section. This describes the
crates that are required at compile-time to run whatever code is in the build
script described by the `build` option in the `[package]` section. Here you need
to use the same major and minor version of `syntex` that is used by the version
of `pnet_macros` you're depending on. And, of course, `pnet_macros` itself.

Finally, you'll need a couple of entries in `[dependencies]` for `pnet` itself
and `pnet_macros_support`, which provides the network types used in the
`#[packet]` macro expansion.

Setting up Your Directory Tree
------------------------------

The basic directory structure will look something like this:

```

Cargo.toml
build.rs
src/
    main.rs
    packet/
        mod.rs
        my_protocol.rs
        my_protocol.rs.in
        
```

This will create a `packet` module that will have your custom packet types
available as submodules, similar to how `pnet::packet` has packet type modules
below it. The `packet` module itself will just do a public export of its
children via the contents of the `packet/mod.rs` file:

```rust

pub mod my_protocol;

```

You would of course add additional lines for any other protocols you added.

The `main.rs` file needs to declare the crates it depends on via `extern crate`,
and it can use the `packet` module to get at the new packet types you've
created. This will look something like:

```rust

extern crate pnet;
extern crate pnet_macros_support;

use pnet::packet::{Packet, MutablePacket};

mod packet;
use packet::my_protocol::{MyProtocolPacket, MutableMyProtocolPacket};

fn main() {

}

```


Creating Packet Source Files
----------------------------

Because `syntex` is a pre-processor that isn't directly plugged into the
compiler framework, you need some way of telling `rustc` to compile the *output*
of `syntex` rather than its input. This is managed by giving the *input* file a
`.in` extension and making a stub source file that simply includes the `syntex`
output.

The stub source file, `src/packet/my_protocol.rs`, will contain the following:

```rust

include!(concat!(env!("OUT_DIR"), "/my_protocol.rs"));

```

The `OUT_DIR` environment variable is set by `cargo` during the execution of the
build script, and it points to the directory within the package source tree
where build output is placed. The `include!` directives and the build script use
this variable to agree on a location for where `syntex`-processed source files
will go.

Finally, there's the actual source file that will be fed to the pre-processor.
This is a very simple example; see the `packet` subdirectory of the `libpnet`
source for many more examples.

```rust

use pnet::packet::PrimitiveValues;
use pnet_macros_support::types::*;

/// Documentation for MyProtocolField
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct MyProtocolField(pub u8);

impl MyProtocolField {
    pub fn new(field_val: u8) -> MyProtocolField {
        MyProtocolField(field_val)
    }
}

impl PrimitiveValues for MyProtocolField {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod MyProtocolFieldValues {
    use packet::my_protocol::MyProtocolField;
    
    /// Documentation for VAULE_FOO
    pub const VALUE_FOO: MyProtocolField = MyProtocolField(0);
    /// Documentation for VALUE_BAR
    pub const VALUE_BAR: MyProtocolField = MyProtocolField(1);
}

/// Documentation for MyProtocol
#[packet]
pub struct MyProtocol {
    #[construct_with(u8)]
    field: MyProtocolField,
    checksum: u16be,
    #[payload]
    payload: Vec<u8>
}

```

Invoking Syntex From Your Build Script
--------------------------------------

To pull everything together, we need to invoke `syntex` within the build script.
This is a simple build script for building just a single packet type; see the
`build.rs` from `libpnet` for an example of how to build a bunch of them:

```rust

extern crate syntex;
extern crate pnet_macros;

use std::env;
use std::path::Path;

fn main() {
    let mut registry = syntex::Registry::new();
    pnet_macros::register(&mut registry);

    let src = Path::new("src/packet/my_protocol.rs.in");
    let dst = Path::new(&env::var_os("OUT_DIR").unwrap()).join("my_protocol.rs");

    registry.expand("", &src, &dst).unwrap();
}

```

Upstreaming Packet Definitions
------------------------------

If the packet modules you've built implement packet types that are generally
useful, please consider contributing them to the `libpnet` project! The method
described here for using `#[packet]` is based on the packet definitions in
`libpnet`, so any packet modules you create should be fairly easy to move over
into the `src/packet` directory of a fork of `libpnet`.

You'll need to modify the stub source file to use `syntex` conditionally based
on the `with-syntex` feature of the `libpnet` crate. It should look like this:

```rust

#[cfg(feature = "with-syntex")]
include!(concat!(env!("OUT_DIR"), "/my_protocol.rs"));

#[cfg(not(feature = "with-syntex"))]
include!("my_protocol.rs.in");

```

And you'll need to update the `build.rs` file to include the base name of your
protocol stub soure file(s) in the static `FILES` array.

Once you've got your new packet type building and tested in the `libpnet` tree,
just push them to your fork on github and open a pull request!
