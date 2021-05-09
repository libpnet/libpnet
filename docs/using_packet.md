Using `#[derive(Packet)]` in Your Own Project
=============================================

The libpnet library provides a few macros to reduce the boilerplate involved in
implementing new protocols. It is based on a Rust proc-macro,
implementing the custom derive `Packet` attribute.

This document is a brief guide to implement a new structure and use the
`#[derive(Packet)]` attribute to derive the implementation.

Upgrading from `syntex`
-----------------------

Previous `pnet` versions used the `syntex` crate to derive the required trait
implementations.

To upgrade from a previous version (`<= 0.27`), use the following steps:
- edit `Cargo.toml` and remove build-dependencies on `syntex`, and `build =
  "build.rs"`
- remove the `build.rs` script (unless used for more than `syntex`)
- The content of included files can be directly in injected to usual source
  files. For example, move the content of `myprotocol.rs.in` to `myprotocol.rs`

Use the `Packet` custom derive. For compatibility, the `packet` custom attribute
is also implemented for an easy transition.

Do one of the following:
- Add a `use pnet_macros::Packet` statement, and replace `#[packet]` with
  `#[derive(Packet)]`
- Or, add `use pnet_macros::packet` and keep the previous declarations

Setting Up `Cargo.toml`
-----------------------

In order to use `Packet`, you need to add a dependency on the `pnet_macros` crate.

Here's an example `Cargo.toml` file:

```toml

[package]
name = "my_pnet_package"
version = "0.1.0"
authors = ["My Name <my.email@mydomain.com>"]
edition = "2018"
[dependencies]
pnet = "*"
pnet_macros_support = "*"
pnet_macros = "*"

```

You need to add a couple of entries in `[dependencies]` for `pnet` itself,
the `pnet_macros` crate, and `pnet_macros_support`, which provides the network types
used in the `#[packet]` macro expansion.

Setting up Your Directory Tree
------------------------------

The basic directory structure can look something like this:

```

Cargo.toml
build.rs
src/
    main.rs
    packet/
        mod.rs
        my_protocol.rs
        
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


Implementing a Packet struct
----------------------------

Declare your structure and add the `#[derive(Packet)]` attribute. The
implementation of all required traits will be derived automatically from the
fields declarations and types.

For some fields, you may have to add annotations, for example if the length of a
field cannot be inferred, or to indicate which field contains the payload.
See [pnet_macros documentation](https://docs.rs/pnet_macros/) for a complete
reference.

Finally, there's the actual source file of a protocol definition.
This is a very simple example; see the `pnet_packet/src` subdirectory of the `libpnet`
source for many more examples.

```rust
use pnet_macros::packet;
use pnet_macros_support::types::*;
use pnet_packet::PrimitiveValues;

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
    use super::MyProtocolField;

    /// Documentation for VALUE_FOO
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
    payload: Vec<u8>,
}
```

Upstreaming Packet Definitions
------------------------------

If the packet modules you've built implement packet types that are generally
useful, please consider contributing them to the `libpnet` project! The method
described here for using `#[packet]` is based on the packet definitions in
`libpnet`, so any packet modules you create should be fairly easy to move over
into the `pnet_packet` directory of a fork of `libpnet`.

Once you've got your new packet type building and tested in the `libpnet` tree,
just push them to your fork on github and open a pull request!
