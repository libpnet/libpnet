# libpnet

Linux ∪ OS X Build Status: [![Linux ∪ OS X Build Status](https://travis-ci.org/libpnet/libpnet.svg)](https://travis-ci.org/libpnet/libpnet)

Windows Build Status: [![Windows Build Status](https://ci.appveyor.com/api/projects/status/9gq1dekigj03u1ym?svg=true)](https://ci.appveyor.com/project/mrmonday/libpnet)

<table>
<tr><td>
<em>The `pnet::packet` module has been moved to `pnet::old_packet`, you will
need to update your code accordingly.</em>
</td></tr>
</table>

`libpnet` provides a cross-platform API for low level networking using Rust.

There are three key components:

 * The old_packet module, allowing safe construction and manipulation of packets
 * The transport module, which allows implementation of transport protocols
 * The datalink module, which allows sending and receiving data link packets directly

## Why?

There are lots of reasons to use low level networking, and many more to do it using Rust. A few are
outlined here:

### Developing Transport Protocols

There are usually two ways to go about developing a new transport layer protocol:

 * Write it in a scripting language such as Python
 * Write it using C

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

API documentation for the lastest build can be found here:
http://octarineparrot.com/assets/libpnet/doc/pnet/.

## Support

Find us on IRC in [#libpnet on freenode](http://webchat.freenode.net/?channels=%23libpnet), or
[#rust on irc.mozilla.org](http://chat.mibbit.com/?server=irc.mozilla.org&channel=%23rust).

## Usage

To use `libpnet` in your project, add the following to your Cargo.toml:

```
[dependencies.pnet]
git = "https://github.com/libpnet/libpnet.git"
```

When developing, use the provided Makefile, which does weird things to make the
tests work properly. Note that root/administrator access is usually required for libpnet.

