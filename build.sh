#!/bin/bash
# Copyright (c) 2014, 2016 Robert Clipsham <robert@octarineparrot.com>
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

# Build script, since cargo doesn't currently work on FreeBSD

[[ "$VERBOSE" == "1" ]] && set -x

RUSTC="$(which rustc)"
RUSTDOC="$(which rustdoc)"
CARGO="$(which cargo)"
SUDO="$(which sudo)"
SYSTEM="$(uname -s)"
TESTER="$CARGO test"
CC="$(which clang || which gcc)"
MACROS_WITH_SYNTEX=0

if [[ -n "$PNET_FEATURES" ]]; then
    PNET_CARGO_FLAGS="--no-default-features --features \"$PNET_FEATURES\""
else
    PNET_CARGO_FLAGS=""
fi

if [[ -n "$PNET_MACROS_FEATURES" ]]; then
    PNET_MACROS_CARGO_FLAGS="--no-default-features --features \"$PNET_MACROS_FEATURES\""
else
    PNET_MACROS_CARGO_FLAGS=""
fi

# FIXME Need to get interface differently on Windows
IFCONFIG=$(which ifconfig)
IPROUTE2=$(which ip)

echo $PNET_MACROS_FEATURES | grep -q with-syntex && MACROS_WITH_SYNTEX=1

PNET_TEST_IFACE=""

if [[ -x "$IFCONFIG" ]]; then
    PNET_TEST_IFACE=$($IFCONFIG | egrep 'UP| active' | \
                      perl -pe '/^[A-z0-9]+:([^\n]|\n\t)*status: active/' | \
                      grep active -B1 | head -n1 | cut -f1 -d:)
fi

if [[ -z "$PNET_TEST_IFACE" && -x "$IPROUTE2" ]]; then
    PNET_TEST_IFACE=$($IPROUTE2 link show | grep 'UP' | head -n1 | \
                      cut -f2 -d: | xargs)
fi

# https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net
if [[ -z "$PNET_TEST_IFACE" && "$SYSTEM" = "Linux" ]]; then
    for file in /sys/class/net/*/carrier; do
        tmp=$(cat "$file")
        if [[ "$tmp" -eq 1 ]]; then
            PNET_TEST_IFACE=$(echo "$file" | cut -d '/' -f 5)
            break
        fi
    done
fi

set -euo pipefail

# FIXME Need to link libraries properly on Windows
build() {
    if [[ -x "$CARGO" ]]; then
        "$CARGO" build $PNET_CARGO_FLAGS --release
    else
        "$RUSTC" src/lib.rs
    fi
}

build_doc() {
    if [[ -x "$CARGO" ]]; then
        "$CARGO" doc $PNET_CARGO_FLAGS
    else
        "$RUSTDOC" src/lib.rs -o target/doc --crate-name pnet
    fi
}

build_test() {
    if [[ -x "$CARGO" ]]; then
        "$CARGO" test --no-run $PNET_CARGO_FLAGS
        "$CARGO" bench --no-run $PNET_CARGO_FLAGS
    else
        "$RUSTC" src/lib.rs --test --out-dir ./target/ -C extra-filename=-no-cargo
    fi
}

run_macro_tests() {
    cd pnet_macros &&
    sh -c "$CARGO test $PNET_MACROS_CARGO_FLAGS" &&
    cd ..
}

run_packet_tests() {
    cd pnet_packet &&
    sh -c "$CARGO test" &&
    cd ..
}

run_test() {
    run_macro_tests &&
    run_packet_tests &&
    export RUST_TEST_THREADS=1 &&
    case "$SYSTEM" in
        Linux)
            "$SUDO" -E sh -c "$CARGO build $PNET_CARGO_FLAGS --release && \
                              $CARGO test $PNET_CARGO_FLAGS && \
                              $CARGO bench --no-run $PNET_CARGO_FLAGS && \
                              $CARGO doc $PNET_CARGO_FLAGS"
        ;;
        FreeBSD|Darwin)
            export PNET_TEST_IFACE
            "$SUDO" -E bash -c "$CARGO build $PNET_CARGO_FLAGS && \
                                $CARGO test $PNET_CARGO_FLAGS && \
                                $CARGO bench --no-run $PNET_CARGO_FLAGS && \
                                $CARGO doc $PNET_CARGO_FLAGS"
        ;;
        MINGW*|MSYS*)
            PNET_TEST_IFACE=$PNET_TEST_IFACE RUST_TEST_THREADS=1 $TESTER
        ;;
        FreeBSD|*)
            echo "Unsupported testing platform"
        ;;
    esac
}

clean() {
    if [[ -x "$CARGO" ]]; then
        "$CARGO" clean $PNET_CARGO_FLAGS
    else
        rm -fr target
    fi
}

benchmarks() {
    [[ "$SYSTEM" != "Darwin" ]] && echo warning: C benchmarks only work on OS X
    "$CC" -W -Wall -O2 benches/c_receiver.c -o target/benches/c_receiver
    "$CC" -W -Wall -O2 benches/c_sender.c -o target/benches/c_sender

    "$RUSTC" -O benches/rs_receiver.rs --out-dir target/benches -L target/release
    "$RUSTC" -O benches/rs_sender.rs --out-dir target/benches -L target/release
}

travis_script() {
    case "$SYSTEM" in
        Linux)
            "$SUDO" sed -i 's/secure_path="/secure_path="\/home\/travis\/.cargo\/bin:/' /etc/sudoers
        ;;
        Darwin)
            echo Defaults secure_path = \"$PATH\" | $SUDO tee -a /etc/sudoers

        ;;
        *)
            echo "Unsupported travis platform"
            exit 1
        ;;
    esac

    run_test
}

mkdir -p target/doc
mkdir -p target/benches

if [[ "$VERBOSE" == "1" ]]; then
    PNET_CARGO_FLAGS="$PNET_CARGO_FLAGS --verbose"
    PNET_MACROS_CARGO_FLAGS="$PNET_MACROS_CARGO_FLAGS --verbose"
    TESTER="$TESTER $PNET_CARGO_FLAGS"
fi

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
    clean)
        clean
    ;;
    benchmarks)
        benchmarks
    ;;
    travis_script)
        travis_script
    ;;
    *)
        build
    ;;
esac

