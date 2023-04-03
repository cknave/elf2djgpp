# DJGPP compiler
DJGPP_GCC = i586-pc-msdosdjgpp-gcc


# Debug target
DEBUG_CFLAGS = -g -O0
DEBUG_BUILD = build/debug
DEBUG_RUST_DIR = rust-lib/target/debug

# Release target
RELEASE_CFLAGS = -s -O3
RELEASE_BUILD = build/release
RELEASE_RUST_DIR = rust-lib/target/release


.PHONY: all clean debug release

all: release

clean:
	rm -rf build
	cd rust-lib; cargo clean


release: $(RELEASE_BUILD)/example.exe

$(RELEASE_BUILD)/example.exe: $(RELEASE_BUILD)/librust_lib.a
	$(DJGPP_GCC) $(RELEASE_CFLAGS) -o $@ example.c $<
	cp -a bin/cwsdpmi.exe $(RELEASE_BUILD)

$(RELEASE_BUILD)/librust_lib.a: rust-lib/src/lib.rs
	sh build-dos-lib.sh --release


debug: $(DEBUG_BUILD)/example.exe

$(DEBUG_BUILD)/example.exe: $(DEBUG_BUILD)/librust_lib.a
	$(DJGPP_GCC) $(DEBUG_CFLAGS) -o $@ example.c $<
	cp -a bin/cwsdpmi.exe $(DEBUG_BUILD)

$(DEBUG_BUILD)/librust_lib.a: rust-lib/src/lib.rs
	sh build-dos-lib.sh
