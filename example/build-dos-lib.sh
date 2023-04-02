#!/bin/sh
set -e
target=debug
extra_opts=

show_usage() {
    echo USAGE: `basename $0` [--release]
    echo
    echo Build librust_lib.a for DOS.
    echo Compiles the dev profile unless --release is given.
}

while :; do
    case $1 in
        -h|--help)
            show_usage
            exit
            ;;
        --release)
            target=release
            extra_opts="$extra_opts --release"
            ;;
        *)
            break
    esac
    shift
done

if test -n "$1"; then
    show_usage
    exit 64
fi

echo "Building $target target..."
cd rust-lib
cargo build -Z build-std --target=i586-unknown-none-gnu.json $extra_opts

# Extract the object files from the ELF static library
mkdir -p ../build/$target/djgpp-lib
cd ../build/$target/djgpp-lib
rm -f *.o
llvm-ar x ../../../rust-lib/target/i586-unknown-none-gnu/"$target"/librust_lib.a

echo "Converting ELF objects to COFF-GO32..."
for f in *.o; do
    elf2djgpp -q -i $f
done
rm -f ../librust_lib.a
llvm-ar cr ../librust_lib.a *.o

echo "build/$target/librust_lib.a built"
