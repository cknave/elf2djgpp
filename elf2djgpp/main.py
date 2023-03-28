import argparse
import contextlib
import shutil
import struct
import sys
import tempfile
import typing

import lief

from . import coff_go32


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_obj')
    parser.add_argument('output_obj', nargs=argparse.OPTIONAL)
    parser.add_argument('-i', '--in-place', action='store_true')
    args = parser.parse_args()
    if args.in_place and args.output_obj:
        parser.error('--in-place and OUTPUT_OBJ are mutually exclusive')

    binary = lief.parse(args.input_obj)
    if binary is None:
        sys.exit(1)
    if binary.header.machine_type != lief.ELF.ARCH.i386:
        print(f'ELF machine type is {binary.header.machine_type.name}, i386 required', file=sys.stderr)
        sys.exit(1)

    coff_obj = convert(binary)
    with output_file(args) as f:
        coff_obj.write(f)

    if args.in_place:
        shutil.move(f.name, args.input_obj)
        print(f'Updated {args.input_obj}')
    else:
        print(f'Converted {args.input_obj} to {f.name}')


def convert(binary: lief.ELF.Binary) -> coff_go32.COFF:
    coff_obj = coff_go32.COFF()

    # Add all the sections
    for section_index, elf_section in enumerate(binary.sections):
        if elf_section.type == lief.ELF.SECTION_TYPES.NULL:
            continue
        elif elf_section.type in (lief.ELF.SECTION_TYPES.STRTAB, lief.ELF.SECTION_TYPES.SYMTAB):
            # We have special handling for symbol table, and we'll make our own string table
            continue
        elif elf_section.type == lief.ELF.SECTION_TYPES.REL:
            # We'll process relocations in the next pass
            continue
        elif elf_section.name.startswith('.text'):
            coff_obj.add_elf_section(elf_section, section_index, coff_go32.COFFSectionFlags.text)
        elif elf_section.name.startswith(('.data', '.rodata')):
            coff_obj.add_elf_section(elf_section, section_index, coff_go32.COFFSectionFlags.data)
        elif elf_section.name.startswith('.bss'):
            coff_obj.add_elf_section(elf_section, section_index, coff_go32.COFFSectionFlags.bss)
        elif elf_section.name.startswith('.debug'):
            # TODO: what debugging sections need extra processing?
            print(f'WARNING: skipping debugging section {elf_section.name}', file=sys.stderr)
            continue
        else:
            if not elf_section.name.startswith('.debug'):
                print(f'WARNING: including unknown section {elf_section.name} as neither text, data, nor bss',
                      file=sys.stderr)
                coff_obj.add_elf_section(elf_section, section_index, section_type=0)

    # Add all the symbols
    for symbol in binary.symbols:
        if symbol.name == '':
            # TODO: I think these should be symbols named after their section
            continue  # why would you have empty symbols?
        coff_obj.add_elf_symbol(symbol)

    # Add all the relocations
    for relocation in binary.relocations:
        section_name, section = None, None
        if relocation.section:
            section_name = relocation.section.name
            section = coff_obj.section_for_elf_section.get(relocation.section)
        reloc_repr = f'address {relocation.address}, type {relocation.type}, section {section_name}'
        if section is None:
            print(f'WARNING: ignoring relocation for skipped section {section_name} ({reloc_repr})', file=sys.stderr)
            continue
        symbol = coff_obj.symbol_for_elf_symbol.get(relocation.symbol)
        if symbol is None:
            print(f'WARNING: ignoring relocation for unused symbol {relocation.symbol.name!r} ({reloc_repr})',
                  file=sys.stderr)
            continue
        if relocation.type not in (lief.ELF.RELOCATION_i386.PC32, lief.ELF.RELOCATION_i386.R32):
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
        filename = f'{args.input_obj}.coff.o'
    return open(filename, 'wb')
