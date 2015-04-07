# Path to compiletest binary (compile from rustc/src/compiletest)
COMPILETEST=compiletest
# Path to rustc
RUSTC=rustc
# Path to Cargo
CARGO=cargo
# pnet_macros library path
PNET_MACROS=$(shell ls target/debug/libpnet_macros*.so)
# pnet library path
PNET=$(shell ls target/debug/deps/libpnet*.so)
# Target triple
TRIPLE=x86_64-unknown-linux-gnu
# Args for compiletest
COMPILETEST_ARGS=--compile-lib-path "" --run-lib-path "" --rustc-path $(RUSTC) --src-base tests/compile-fail \
				 --build-base target/tests --aux-base tests/aux --stage-id "" \
				 --android-cross-path "" --target $(TRIPLE) --target-rustcflags \
				 "--extern pnet=$(PNET) --extern pnet_macros=$(PNET_MACROS)"

test:
	#$(CARGO) test
	mkdir -p target/tests
	$(COMPILETEST) --mode compile-fail $(COMPILETEST_ARGS) compile-fail
