"""Minimum viable DJGPP COFF-GO32 structures.

http://www.delorie.com/djgpp/doc/coff/

"""

from __future__ import annotations

import dataclasses
import enum
import io
import struct
import sys
import typing

import lief

MAX_NAME_LEN = 8
"""Maximum size of short section/symbol names."""

STRING_TABLE_BASE_OFFSET = 4
"""Offset the beginning of the string table to skip over the uint32 that precedes it."""

FIX_EXTERN_SYMBOLS = {
    'compiler_builtins::mem::memset': 'memset',
    'compiler_builtins::mem::memcmp': 'memcmp',
    'compiler_builtins::mem::bcmp': 'bcmp',
    'compiler_builtins::mem::strlen': 'strlen',
    'compiler_builtins::mem::memcpy': 'memcpy',
    'compiler_builtins::mem::memmove': 'memmove',
}
"""A compiler-builtins bug (or cargo bug?) causes these undefined symbols to end up in the resulting library:
https://github.com/rust-lang/compiler-builtins/issues/347

Link them to the real DJGPP functions instead by renaming the symbols, what could possibly go wrong?"""


class COFFFileFlags(enum.IntFlag):
    relocs_stripped = 0x0001
    executable = 0x0002
    line_nums_stripped = 0x0004
    local_syms_stripped = 0x0008
    machine_32bit_little_endian = 0x0100


class COFFSectionFlags(enum.IntFlag):
    text = 0x0020
    data = 0x0040
    bss = 0x0080


class COFFRelocationType(enum.IntEnum):
    absolute = 0x0006
    relative = 0x0014


class StringTable:

    def __init__(self):
        self._contents = io.BytesIO()
        self._string_offsets: dict[bytes, StringTableOffset] = dict()

    def add(self, value: bytes) -> StringTableOffset:
        index = StringTableOffset(self._contents.tell() + STRING_TABLE_BASE_OFFSET)
        self._contents.write(value)
        self._contents.write(b'\x00')
        self._string_offsets[value] = index
        return index

    def get_offset(self, value: bytes) -> StringTableOffset | None:
        return self._string_offsets.get(value)

    def get_string(self, offset: int) -> bytes:
        end_idx = self.data[offset:].find(b'\x00')
        if end_idx == -1:
            return self.data[offset:]
        return self.data[offset:end_idx]

    @property
    def data(self) -> bytes:
        return self._contents.getvalue()


class StringTableOffset(int):
    pass


@dataclasses.dataclass
class COFF:
    sections: list[Section] = dataclasses.field(default_factory=list)
    symbols: list[Symbol] = dataclasses.field(default_factory=list)
    strings: StringTable = dataclasses.field(default_factory=StringTable)
    section_for_elf_index: dict[int, Section] = dataclasses.field(default_factory=dict)
    section_for_elf_section_name: dict[str, Section] = dataclasses.field(default_factory=dict)
    symbol_for_elf_symbol_key: dict[str, Symbol] = dataclasses.field(default_factory=dict)
    index_for_symbol: dict[Symbol, int] = dataclasses.field(default_factory=dict)

    def add_elf_section(self, elf_section: lief.Section, elf_section_index: int, section_type: int = 0) -> Section:
        name = elf_section.name.encode('ascii')
        if len(name) > MAX_NAME_LEN:
            name = self.strings.add(name)
        section = Section(
            name,
            COFFSectionFlags(section_type),
            number=len(self.sections) + 1,  # section numbers are 1-based
            address=elf_section.virtual_address,
            size=elf_section.size,
            data=bytearray(elf_section.content),
        )
        self.sections.append(section)
        self.section_for_elf_index[elf_section_index] = section
        if elf_section.name in self.section_for_elf_section_name:
            raise RuntimeError(f'Attempted to add section {elf_section.name!r} twice')
        self.section_for_elf_section_name[elf_section.name] = section
        return section

    def add_elf_symbol(self, elf_symbol: lief.Symbol) -> Symbol | None:
        if elf_symbol.type == lief.ELF.SYMBOL_TYPES.SECTION:
            # Special case: section symbols
            name = self.section_for_elf_index[elf_symbol.shndx].name
            section_number = self.section_for_elf_index[elf_symbol.shndx].number
            storage_class = SymbolStorageClass.static
        else:
            # Normal case: every other kind of symbol
            name = elf_symbol.name.encode('ascii')

            # Deal with nonexistent compiler-builtins symbols
            is_undefined = elf_symbol.shndx == 0  # Section 0 seems to be for undefined symbols
            if is_undefined:
                for prefix, replacement in FIX_EXTERN_SYMBOLS.items():
                    if elf_symbol.demangled_name.startswith(prefix):
                        print(f'Replacing bad extern "{elf_symbol.demangled_name}" with "{replacement}"')
                        name = replacement.encode('ascii')
                        break

            if is_undefined or elf_symbol.is_variable or elf_symbol.is_function:
                # Add the DJGPP underscore prefix
                name = b'_' + name

            if len(name) > MAX_NAME_LEN:
                # Replace with a string table reference if too long
                name = self.strings.add(name)

            section_number = None
            if elf_symbol.type == lief.ELF.SYMBOL_TYPES.FILE:
                storage_class = SymbolStorageClass.file_name
                section_number = NonSectionSymbol.debugging
            elif elf_symbol.is_function and elf_symbol.binding == lief.ELF.SYMBOL_BINDINGS.LOCAL:
                storage_class = SymbolStorageClass.label
            elif elf_symbol.binding == lief.ELF.SYMBOL_BINDINGS.GLOBAL:
                storage_class = SymbolStorageClass.external
            else:
                storage_class = SymbolStorageClass.static

            if section_number is None and elf_symbol.shndx == 0:
                # Section 0 seems to be for undefined symbols
                section_number = NonSectionSymbol.extern

            if section_number is None:
                try:
                    section_number = self.section_for_elf_index[elf_symbol.shndx].number
                except KeyError:
                    print(f'WARNING: Skipping symbol {elf_symbol.name} from skipped section', file=sys.stderr)
                    return None

        symbol = Symbol(name, elf_symbol.value, section_number, storage_class)
        key = self._elf_symbol_key(elf_symbol)
        if key in self.symbol_for_elf_symbol_key:
            raise RuntimeError(f'Attempted to insert symbol with key {key!r} twice')
        self.symbol_for_elf_symbol_key[key] = symbol
        self.index_for_symbol[symbol] = len(self.symbols)
        self.symbols.append(symbol)
        return symbol

    def get_coff_symbol_for_elf(self, elf_symbol: lief.ELF.Symbol) -> Symbol | None:
        key = self._elf_symbol_key(elf_symbol)
        return self.symbol_for_elf_symbol_key.get(key)

    def add_relocation(self, elf_relocation: lief.ELF.Relocation) -> Relocation:
        symbol = self.get_coff_symbol_for_elf(elf_relocation.symbol)
        if elf_relocation.type in (lief.ELF.RELOCATION_i386.PC32, lief.ELF.RELOCATION_i386.PLT32):
            rel_type = COFFRelocationType.relative
        elif elf_relocation.type == lief.ELF.RELOCATION_i386.R32:
            rel_type = COFFRelocationType.absolute
        else:
            raise TypeError(f'Cannot represent relocation type {elf_relocation.type}')
        relocation = Relocation(elf_relocation.address, symbol, rel_type, parent=self)

        section = self.section_for_elf_section_name[elf_relocation.section.name]
        section.relocations.append(relocation)
        return relocation

    def write(self, f: typing.BinaryIO) -> None:
        from . import binfmt

        # Keep track of where the data for each section will start, beginning after the headers
        data_offset = (binfmt.struct_size(binfmt.COFFFileHeader) +
                       (binfmt.struct_size(binfmt.COFFSectionHeader) * len(self.sections)))

        # Write the COFF headers
        file_header = binfmt.COFFFileHeader.from_coff(self)
        binfmt.struct_write(file_header, f)
        for section in self.sections:
            section_header = binfmt.COFFSectionHeader.from_section(section, data_offset)
            binfmt.struct_write(section_header, f)
            data_offset += len(section.data)
            data_offset += binfmt.struct_size(binfmt.COFFRelocation) * len(section.relocations)
            # TODO: lineno offset

        # Write the data, relocs, and line numbers for each section
        for section in self.sections:
            f.write(section.data)
            for reloc in section.relocations:
                reloc_data = binfmt.COFFRelocation.from_relocation(reloc)
                binfmt.struct_write(reloc_data, f)
            # TODO: lineno data

        # Write the symbol table after all sections
        for symbol in self.symbols:
            symbol_bin = binfmt.COFFSymbol.from_symbol(symbol)
            binfmt.struct_write(symbol_bin, f)

        # Write the string table length as a uint32 before dumping all the strings
        f.write(struct.pack('<I', len(self.strings.data) + STRING_TABLE_BASE_OFFSET))
        f.write(self.strings.data)

    @staticmethod
    def _elf_symbol_key(symbol: lief.ELF.Symbol) -> str:
        # Symbol names don't have to be unique, so make a more unique key
        return f'{symbol.name}.{symbol.shndx}'


@dataclasses.dataclass
class Section:
    name: bytes | StringTableOffset
    type: COFFSectionFlags
    number: int
    address: int
    size: int
    data: bytearray
    relocations: list[Relocation] = dataclasses.field(default_factory=list)


class NonSectionSymbol(enum.IntEnum):
    extern = 0
    constant = -1
    debugging = -2


class SymbolStorageClass(enum.IntEnum):
    external = 2  # globals and externs
    static = 3  # section names
    label = 6  # locals
    file_name = 103


@dataclasses.dataclass(frozen=True)
class Symbol:
    name: bytes | StringTableOffset
    value: int
    section_number: int | NonSectionSymbol  # 1-based
    storage_class: SymbolStorageClass
    # TODO: aux support needed?


@dataclasses.dataclass
class Relocation:
    address: int
    symbol: Symbol
    type: COFFRelocationType
    parent: COFF
