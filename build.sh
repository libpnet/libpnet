#!/bin/bash
# Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

# Build script, since cargo doesn't currently work on FreeBSD

[[ "$VERBOSE" == "1" ]] && set -x

RUSTC=$(which rustc)
RUSTDOC=$(which rustdoc)
CARGO=$(which cargo)
SUDO=$(which sudo)
SYSTEM=$(uname -s)
TESTER="$CARGO test"

# FIXME Need to get interface differently on Windows
PNET_TEST_IFACE=$(ifconfig | egrep 'UP| active' | \
                  perl -pe '/^[A-z0-9]+:([^\n]|\n\t)*status: active/' | \
                  grep active -B1 | head -n1 | cut -f1 -d:)

# FIXME Need to link libraries properly on Windows
build() {
    if [[ -x "$CARGO" ]]; then
        $CARGO build
    else
        $RUSTC src/lib.rs
    fi
}

build_doc() {
    if [[ -x "$CARGO" ]]; then
        $CARGO doc
    else
        $RUSTDOC src/lib.rs -o target/doc --crate-name pnet
    fi
}

build_test() {
    if [[ -x "$CARGO" ]]; then
        $CARGO test --no-run
    else
        $RUSTC src/lib.rs --test --out-dir ./target/ -C extra-filename=-no-cargo
    fi
}

run_test() {
    build_test &&
    echo "Setting permissions for test suite - enter sudo password if prompted" &&
    case "$SYSTEM" in
        Linux)
            if [[ "$(id -u)" != "0" ]]; then
                $SUDO setcap cap_net_raw+ep target/pnet-*;
            fi
            RUST_TEST_TASKS=1 $TESTER
        ;;
        FreeBSD|Darwin)
            $SUDO PNET_TEST_IFACE=$PNET_TEST_IFACE RUST_TEST_TASKS=1 $TESTER
        ;;
        MINGW*|MSYS*)
            PNET_TEST_IFACE=$PNET_TEST_IFACE RUST_TEST_TASKS=1 $TESTER
        ;;
        *)
            echo "Unsupported testing platform"
        ;;
    esac
}

mkdir -p target/doc

if [[ ! -x "$CARGO" ]]; then
    TESTER='./target/pnet-*'
fi

case "$1" in
    test)
        run_test
    ;;
    doc)
        build_doc
    ;;
    *)
        build
    ;;
esac
