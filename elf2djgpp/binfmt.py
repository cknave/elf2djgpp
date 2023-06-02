"""DJGPP COFF-GO32 binary format.

http://www.delorie.com/djgpp/doc/coff/

"""
from __future__ import annotations

import dataclasses
import functools
import struct
import time
import typing

from . import coff_go32

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

COFF_MAGIC = b'\x4c\x01'

# Dataclass field types for fields that should be written to disk.
# ``struct_fmt`` metadata contains the ``struct`` format string for the field.
char = lambda n, **kwargs: dataclasses.field(metadata={'struct_fmt': f'{n}s'}, **kwargs)
int16_t = functools.partial(dataclasses.field, metadata={'struct_fmt': 'h'})
uint8_t = functools.partial(dataclasses.field, metadata={'struct_fmt': 'B'})
uint16_t = functools.partial(dataclasses.field, metadata={'struct_fmt': 'H'})
uint32_t = functools.partial(dataclasses.field, metadata={'struct_fmt': 'I'})


@dataclasses.dataclass
class COFFFileHeader:
    magic: bytes = char(2)
    num_sections: int = uint16_t()
    timestamp: int = uint32_t()
    symbols_ptr: int = uint32_t()
    num_symbols: int = uint32_t()
    opt_header_size: int = uint16_t()
    flags: coff_go32.COFFFileFlags = uint16_t()

    @classmethod
    def from_coff(cls, coff: coff_go32.COFF) -> Self:
        # Calculate the size of this header and all the sections to find the offset of the symbol table
        header_and_sections_len = struct_size(cls)
        for section in coff.sections:
            header_and_sections_len += struct_size(COFFSectionHeader)
            header_and_sections_len += len(section.data)
            header_and_sections_len += struct_size(COFFRelocation) * len(section.relocations)
            # TODO: line nums

        flags = coff_go32.COFFFileFlags.machine_32bit_little_endian
        # TODO: where are line numbers?
        flags |= coff_go32.COFFFileFlags.line_nums_stripped
        # TODO: how do we know if local syms are stripped?
        flags |= coff_go32.COFFFileFlags.local_syms_stripped
        # TODO: how do we know if relocations are stripped?
        if not any(section.relocations for section in coff.sections):
            flags |= coff_go32.COFFFileFlags.relocs_stripped

        return cls(
            magic=COFF_MAGIC,
            num_sections=len(coff.sections),
            timestamp=int(time.time()),
            symbols_ptr=header_and_sections_len,
            num_symbols=len(coff.symbols),
            opt_header_size=0,
            flags=flags,
        )


@dataclasses.dataclass
class COFFSectionHeader:
    name: bytes = char(coff_go32.MAX_NAME_LEN)
    physical_address: int = uint32_t()
    virtual_address: int = uint32_t()
    size: int = uint32_t()
    raw_data_ptr: int = uint32_t()
    relocations_ptr: int = uint32_t()
    line_nums_ptr: int = uint32_t()
    num_relocations: int = uint16_t()
    num_line_nums: int = uint16_t()
    flags: coff_go32.COFFSectionFlags = uint32_t()

    @classmethod
    def from_section(cls, section: coff_go32.Section, raw_data_offset: int) -> Self:
        name = section.name
        if isinstance(name, coff_go32.StringTableOffset):
            name = f'/{name}'.encode('ascii')

        raw_data_ptr = 0
        if len(section.data) > 0:
            raw_data_ptr = raw_data_offset

        relocations_ptr = 0
        num_relocations = len(section.relocations)
        if num_relocations > 0:
            relocations_ptr = raw_data_offset + len(section.data)

        # TODO: line nums?
        line_nums_ptr = 0
        num_line_nums = 0

        return cls(
            name=name,
            physical_address=section.address,
            virtual_address=section.address,
            size=len(section.data),
            raw_data_ptr=raw_data_ptr,
            relocations_ptr=relocations_ptr,
            line_nums_ptr=line_nums_ptr,
            num_relocations=num_relocations,
            num_line_nums=num_line_nums,
            flags=section.type,
        )


@dataclasses.dataclass
class COFFSymbol:
    name: bytes = char(coff_go32.MAX_NAME_LEN)
    value: int = uint32_t()
    section_number: int = int16_t()
    type: int = uint16_t()
    storage_class: int = uint8_t()
    num_aux: int = uint8_t()

    @classmethod
    def from_symbol(cls, symbol: coff_go32.Symbol) -> Self:
        name = symbol.name
        if isinstance(name, coff_go32.StringTableOffset):
            # String reference is four 00 bytes followed by a uint32 of the string table offset
            name = struct.pack('<II', 0, name)
        return cls(
            name,
            symbol.value,
            symbol.section_number,
            type=0,
            storage_class=symbol.storage_class,
            num_aux=0,
        )


@dataclasses.dataclass
class COFFRelocation:
    address: int = uint32_t()
    symbol_idx: int = uint32_t()
    relocation_type: coff_go32.COFFRelocationType = uint16_t()

    @classmethod
    def from_relocation(cls, relocation: coff_go32.Relocation) -> Self:
        symbol_idx = relocation.parent.index_for_symbol[relocation.symbol]
        return cls(relocation.address, symbol_idx, relocation.type)


def struct_write(obj: typing.Any, f: typing.BinaryIO) -> None:
    if not dataclasses.is_dataclass(obj) or isinstance(obj, type):
        raise ValueError('Dataclass instance required')
    for field in dataclasses.fields(obj):
        data = struct.pack('<' + field.metadata['struct_fmt'], getattr(obj, field.name))
        f.write(data)


def struct_size(obj: typing.Any) -> int:
    if not dataclasses.is_dataclass(obj):
        raise ValueError('Dataclass required')
    total = 0
    for field in dataclasses.fields(obj):
        total += struct.calcsize(field.metadata['struct_fmt'])
    return total
