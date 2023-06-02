from __future__ import annotations

import argparse
import contextlib
import os.path
import shutil
import struct
import sys
import tempfile
import typing

import lief

from . import coff_go32

IGNORE_ELF_SECTION_TYPES = {
    lief.ELF.SECTION_TYPES.NULL,  # WHY?
    lief.ELF.SECTION_TYPES.STRTAB,  # We build our own string table
    lief.ELF.SECTION_TYPES.SYMTAB,  # We process symbols after all sections have been processed
    lief.ELF.SECTION_TYPES.REL,  # We process relocations after sections and symbols
}
"""ELF section types that should not be automatically copied to the resulting COFF."""

COFF_SECTION_TYPE_PREFIXES: dict[tuple[str, ...], coff_go32.COFFSectionFlags | int] = {
    ('.text', ): coff_go32.COFFSectionFlags.text,
    ('.data', '.rodata'): coff_go32.COFFSectionFlags.data,
    ('.bss', ): coff_go32.COFFSectionFlags.bss,
    ('.debug', '.note.GNU-stack'): 0,
}
"""Mapping from a tuple of section name prefixes to their corresponding COFF section type."""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_obj')
    parser.add_argument('output_obj', nargs=argparse.OPTIONAL)
    parser.add_argument('-i', '--in-place', action='store_true')
    parser.add_argument('-q', '--quiet', action='store_true')
    args = parser.parse_args()
    if args.in_place and args.output_obj:
        parser.error('--in-place and OUTPUT_OBJ are mutually exclusive')

    print_quiet = dont_print if args.quiet else print

    binary = lief.parse(args.input_obj)
    if binary is None:
        sys.exit(1)
    if binary.format != lief.EXE_FORMATS.ELF:
        print(f'Binary type is {binary.format.name}.  ELF is required.')
        sys.exit(1)
    if binary.header.machine_type != lief.ELF.ARCH.i386:
        print(f'ELF machine type is {binary.header.machine_type.name}.  i386 is required.', file=sys.stderr)
        sys.exit(1)

    coff_obj = convert(binary)
    with output_file(args) as f:
        coff_obj.write(f)

    if args.in_place:
        shutil.move(f.name, args.input_obj)
        print_quiet(f'Updated {args.input_obj}')
    else:
        print_quiet(f'Converted {args.input_obj} to {f.name}')


def convert(binary: lief.ELF.Binary) -> coff_go32.COFF:
    coff_obj = coff_go32.COFF()

    # Add all the sections
    for section_index, elf_section in enumerate(binary.sections):
        if elf_section.type in IGNORE_ELF_SECTION_TYPES:
            continue
        for prefixes, st in COFF_SECTION_TYPE_PREFIXES.items():
            if elf_section.name.startswith(prefixes):
                section_type = st
                break
        else:
            print(f'WARNING: including unknown section {elf_section.name} ({elf_section.type}) as non-text/data/bss',
                  file=sys.stderr)
            section_type = 0
        coff_obj.add_elf_section(elf_section, section_index, section_type)

    # Add all the symbols
    for symbol in binary.symbols:
        if symbol.name == '' and symbol.type == lief.ELF.SYMBOL_TYPES.NOTYPE:
            continue  # WHY?
        if symbol.type == lief.ELF.SYMBOL_TYPES.SECTION and symbol.shndx not in coff_obj.section_for_elf_index:
            section_name = binary.sections[symbol.shndx].name
            print(f'WARNING: skipping section symbol for unused section {section_name}')
            continue
        coff_obj.add_elf_symbol(symbol)

    # Add all the relocations
    for relocation in binary.relocations:
        section_name, section = None, None
        if relocation.section:
            section_name = relocation.section.name
            section = coff_obj.section_for_elf_section_name.get(relocation.section.name)
        reloc_repr = f'address {relocation.address}, type {relocation.type}, section {section_name}'
        if section is None:
            print(f'WARNING: ignoring relocation for skipped section {section_name} ({reloc_repr})', file=sys.stderr)
            continue
        symbol = coff_obj.get_coff_symbol_for_elf(relocation.symbol)
        if symbol is None:
            print(f'WARNING: ignoring relocation for unused symbol {relocation.symbol.name!r} ({reloc_repr})',
                  file=sys.stderr)
            continue
        if relocation.type not in (lief.ELF.RELOCATION_i386.PC32, lief.ELF.RELOCATION_i386.R32,
                                   lief.ELF.RELOCATION_i386.PLT32):
            print(
                f'WARNING: ignoring relocation with unusable type {relocation.type} for symbol '
                f'{relocation.symbol.name!r} ({reloc_repr})',
                file=sys.stderr)
            continue
        coff_obj.add_relocation(relocation)

    # Fix the data for relative relocations.
    # In our clang ELF binaries, the target operand points to its *own address* relative to the section start.
    # But in our DJGPP binaries, the target operand points to the section start.
    # So for relocation to work properly, we need to fix all those addresses to point to the section start.
    for section in coff_obj.sections:
        for relocation in section.relocations:
            if relocation.type == coff_go32.COFFRelocationType.relative:
                addr = relocation.address
                rel_to_start = -(addr + 4)
                section.data[addr:addr + 4] = struct.pack('<i', rel_to_start)

    return coff_obj


def output_file(args: argparse.Namespace) -> contextlib.AbstractContextManager[typing.BinaryIO]:
    if args.in_place:
        return tempfile.NamedTemporaryFile('wb', prefix='elf2djgpp-', delete=False)
    filename = args.output_obj
    if filename is None:
        filebase, ext = os.path.splitext(args.input_obj)
        ext = ext or '.o'
        filename = f'{filebase}.coff{ext}'
    return open(filename, 'wb')


def dont_print(*args, **kwargs):
    """Just don't print"""
