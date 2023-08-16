# elf2djgpp

## What is this?

- A command line tool, `elf2djgpp`, that will convert x86 ELF object files to DJGPP COFF-GO32
  objects.
- An example project where both C and Rust functions are used, and DJGPP is used as Rust's global
  allocator.

## What does it do?

1. An ELF object is loaded using the [elf crate](https://docs.rs/elf/latest/elf/)
2. Symbols get prefixed with `_` as DJGPP expects.
3. Code sections with relative relocations are modified so that the address operands point to
   the section start as DJGPP expects.
4. [Missing `compiler_builtins` symbols](https://github.com/rust-lang/wg-cargo-std-aware/issues/53)
   are replaced with DJGPP functions.

## How do I try it?

You'll need these installed:

- Rust nightly
- DJGPP (`i586-pc-msdosdjgpp-djgpp` in your `$PATH`)

Build release or debug binaries:

    (.venv) $ cd example
    (.venv) $ make release  # creates build/release/example.exe
    (.venv) $ make debug    # creates build/debug/example.exe (much larger)

## Should I use this for anything serious?

No. This is an exploration of file formats that ended up producing a useful script, but it's
untested and probably not complete.

