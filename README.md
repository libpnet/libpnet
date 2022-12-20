# libpnet [![Crates.io](https://img.shields.io/crates/v/pnet.svg)](https://crates.io/crates/pnet) ![License](https://img.shields.io/crates/l/pnet.svg) [![Documentation](https://docs.rs/pnet/badge.svg)](https://docs.rs/pnet/)

Build Status: [![Build Status](https://github.com/libpnet/libpnet/actions/workflows/ci.yml/badge.svg)](https://github.com/libpnet/libpnet/actions/workflows/ci.yml)

Discussion and support:

 * Live chat on IRC - [#libpnet on irc.libera.chat](https://kiwiirc.com/nextclient/irc.libera.chat/libpnet?nick=pnet-user42)
 * [GitHub Discussions](https://github.com/libpnet/libpnet/discussions)

`libpnet` provides a cross-platform API for low level networking using Rust.

There are four key components:

 * The `packet` module, allowing safe construction and manipulation of packets;
 * The `pnet_macros` crate, providing infrastructure for the packet module;
 * The `transport` module, which allows implementation of transport protocols;
 * The `datalink` module, which allows sending and receiving data link packets directly.

## Why?

There are lots of reasons to use low level networking, and many more to do it using Rust. A few are
outlined here:

### Developing Transport Protocols

There are usually two ways to go about developing a new transport layer protocol:

 * Write it in a scripting language such as Python;
 * Write it using C.

The former is great for trying out new ideas and rapid prototyping, however not so great as a
real-world implementation. While you can usually get reasonable performance out of these
implementations, they're generally significantly slower than an implementation in C, and not
suitable for any "heavy lifting".

The next option is to write it in C - this will give you great performance, but comes with a number
of other issues:

 * Lack of memory safety - this is a huge source of security vulnerabilities and other bugs in
   C-based network stacks. It is far too easy to forget a bounds check or use a pointer after it is
   freed.
 * Lack of thread safety - you have to be very careful to make sure the correct locks are used, and
   used correctly.
 * Lack of high level abstractions - part of the appeal of scripting languages such as Python is
   the higher level of abstraction which enables simpler APIs and ease of programming.

Using `libpnet` and Rust, you get the best of both worlds. The higher level abstractions, memory
and thread safety, alongside the performance of C.

### Network Utilities

Many networking utilities such as ping and traceroute rely on being able to manipulate network and
transport headers, which isn't possible with standard networking stacks such as those provided by
`std::io::net`.

### Data Link Layer

It can be useful to work directly at the data link layer, to see packets as they are "on the wire".
There are lots of uses for this, including network diagnostics, packet capture and traffic shaping.

## Documentation

API documentation for the latest build can be found here: https://docs.rs/pnet/

## Usage

To use `libpnet` in your project, add the following to your Cargo.toml:

```
[dependencies.pnet]
version = "0.31.0"
```

`libpnet` should work with the latest stable version of Rust.

When running the test suite, there are a number of networking tests which will
likely fail - the easiest way to workaround this is to run `cargo test` as a
root or administrative user. This can often be avoided, however it is more
involved.

### Windows

There are three requirements for building on Windows:

 * You must use a version of Rust which uses the MSVC toolchain
 * You must have [WinPcap](https://www.winpcap.org/) or [npcap](https://nmap.org/npcap/) installed
   (tested with version WinPcap 4.1.3) (If using npcap, make sure to install with the "Install Npcap in WinPcap API-compatible Mode")
 * You must place `Packet.lib` from the [WinPcap Developers pack](https://www.winpcap.org/devel.htm)
   in a directory named `lib`, in the root of this repository. Alternatively, you can use any of the
   locations listed in the `%LIB%`/`$Env:LIB` environment variables. For the 64 bit toolchain it is
   in `WpdPack/Lib/x64/Packet.lib`, for the 32 bit toolchain, it is in `WpdPack/Lib/Packet.lib`.
