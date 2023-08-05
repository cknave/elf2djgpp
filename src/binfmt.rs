use crate::coff_go32::{
    Coff, CoffFileFlags, CoffSectionType, Name, Relocation, Section, Symbol, MAX_NAME_LEN,
};
use std::io::{Result, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const COFF_MAGIC: &[u8; 2] = b"\x4c\x01";

pub struct CoffFileHeader {
    pub magic: [u8; 2],
    pub num_sections: u16,
    pub timestamp: u32,
    pub symbols_ptr: u32,
    pub num_symbols: u32,
    pub opt_header_size: u16,
    pub flags: u16,
}

impl CoffFileHeader {
    pub fn from_coff(coff: &Coff) -> Self {
        // Calculate the size of this header and all the sections to find the offset of the
        // symbol table.
        let mut header_and_sections_len = Self::SIZE;
        for section in coff.sections.iter() {
            let section = section.borrow();
            header_and_sections_len += CoffSectionHeader::SIZE;
            header_and_sections_len += section.size_on_disk() as usize;
            header_and_sections_len += CoffRelocation::SIZE * section.relocations.len();
            // TODO: line nums
        }

        let mut flags = CoffFileFlags::Machine32BitLittleEndian;
        // TODO: where are line numbers?
        flags |= CoffFileFlags::LineNumsStripped;
        // TODO: how do we know if local syms are stripped?
        flags |= CoffFileFlags::LocalSymsStripped;
        if coff
            .sections
            .iter()
            .find(|s| !s.borrow().relocations.len() > 0)
            .is_none()
        {
            flags |= CoffFileFlags::RelocsStripped;
        }

        Self {
            magic: COFF_MAGIC.clone(),
            num_sections: coff.sections.len() as u16,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            symbols_ptr: header_and_sections_len as u32,
            num_symbols: coff.symbols.len() as u32,
            opt_header_size: 0,
            flags: flags.bits(),
        }
    }
}

impl CoffSerialize for CoffFileHeader {
    const SIZE: usize = 20;

    fn serialize<W: Write>(&self, serializer: &mut CoffWriter<W>) -> Result<usize> {
        let mut written = 0;
        written += serializer.write_bytes(&self.magic)?;
        written += serializer.write_u16(self.num_sections)?;
        written += serializer.write_u32(self.timestamp)?;
        written += serializer.write_u32(self.symbols_ptr)?;
        written += serializer.write_u32(self.num_symbols)?;
        written += serializer.write_u16(self.opt_header_size)?;
        written += serializer.write_u16(self.flags)?;
        assert_eq!(written, Self::SIZE);
        Ok(written)
    }
}

pub struct CoffSectionHeader {
    name: [u8; MAX_NAME_LEN],
    physical_address: u32,
    virtual_address: u32,
    size: u32,
    raw_data_ptr: u32,
    relocations_ptr: u32,
    line_nums_ptr: u32,
    num_relocations: u16,
    num_line_nums: u16,
    flags: CoffSectionType,
}

impl CoffSectionHeader {
    pub fn from_section(section: &Section, raw_data_offset: u32) -> Self {
        let name = match section.name {
            Name::Literal(s) => s,
            Name::StringTableIndex(idx) => {
                let mut buf = [0u8; MAX_NAME_LEN];
                write!(&mut buf[..], "/{idx}").unwrap();
                buf
            }
        };

        let raw_data_ptr = if section.size > 0 { raw_data_offset } else { 0 };

        let num_relocations = section.relocations.len() as u16;
        let relocations_ptr = if num_relocations > 0 {
            raw_data_offset + section.size_on_disk()
        } else {
            0
        };

        // TODO: line nums?
        let line_nums_ptr = 0;
        let num_line_nums = 0;

        Self {
            name,
            physical_address: section.address,
            virtual_address: section.address,
            size: section.size,
            raw_data_ptr,
            relocations_ptr,
            line_nums_ptr,
            num_relocations,
            num_line_nums,
            flags: CoffSectionType::Unknown,
        }
    }
}

impl CoffSerialize for CoffSectionHeader {
    const SIZE: usize = 40;

    fn serialize<W: Write>(&self, serializer: &mut CoffWriter<W>) -> Result<usize> {
        let mut written = 0;
        written += serializer.write_bytes(&self.name)?;
        written += serializer.write_u32(self.physical_address)?;
        written += serializer.write_u32(self.virtual_address)?;
        written += serializer.write_u32(self.size)?;
        written += serializer.write_u32(self.raw_data_ptr)?;
        written += serializer.write_u32(self.relocations_ptr)?;
        written += serializer.write_u32(self.line_nums_ptr)?;
        written += serializer.write_u16(self.num_relocations)?;
        written += serializer.write_u16(self.num_line_nums)?;
        written += serializer.write_u32(self.flags as u32)?;
        assert_eq!(written, Self::SIZE);
        Ok(written)
    }
}

pub struct CoffSymbol {
    name: [u8; MAX_NAME_LEN],
    value: u32,
    section_number: i16,
    symbol_type: u16,
    storage_class: u8,
    num_aux: u8,
}

impl CoffSymbol {
    pub fn from_symbol(symbol: &Symbol) -> Self {
        let name = match symbol.name {
            Name::Literal(s) => s,
            Name::StringTableIndex(idx) => {
                // String reference is four 00 bytes followed by a uint32 of the string table offset
                let mut buf = [0u8; MAX_NAME_LEN];
                buf[4..8].copy_from_slice(&idx.to_le_bytes());
                buf
            }
        };
        Self {
            name,
            value: symbol.value,
            section_number: symbol.section_number.bits(),
            symbol_type: 0,
            storage_class: symbol.storage_class.clone() as u8,
            num_aux: 0,
        }
    }
}

impl CoffSerialize for CoffSymbol {
    const SIZE: usize = 18;

    fn serialize<W: Write>(&self, serializer: &mut CoffWriter<W>) -> Result<usize> {
        let mut written: usize = 0;
        written += serializer.write_bytes(&self.name)?;
        written += serializer.write_u32(self.value)?;
        written += serializer.write_i16(self.section_number)?;
        written += serializer.write_u16(self.symbol_type)?;
        written += serializer.write_u8(self.storage_class)?;
        written += serializer.write_u8(self.num_aux)?;
        assert_eq!(written, Self::SIZE);
        Ok(written)
    }
}

pub struct CoffRelocation {
    address: u32,
    symbol_idx: u32,
    relocation_type: u16,
}

impl CoffRelocation {
    pub fn from_relocation(reloc: &Relocation) -> Self {
        Self {
            address: reloc.address,
            symbol_idx: reloc.symbol.borrow().index as u32,
            relocation_type: reloc.relocation_type as u16,
        }
    }
}

impl CoffSerialize for CoffRelocation {
    const SIZE: usize = 10;

    fn serialize<W: Write>(&self, serializer: &mut CoffWriter<W>) -> Result<usize> {
        let mut written = 0;
        written += serializer.write_u32(self.address)?;
        written += serializer.write_u32(self.symbol_idx)?;
        written += serializer.write_u16(self.relocation_type)?;
        assert_eq!(written, Self::SIZE);
        Ok(written)
    }
}

pub trait CoffSerialize {
    const SIZE: usize;
    fn serialize<W: Write>(&self, serializer: &mut CoffWriter<W>) -> Result<usize>;
}

pub trait CoffSerializer {
    fn write_chars(&mut self, chars: &[u8]) -> Result<usize>;
    fn write_i16(&mut self, value: &i16) -> Result<usize>;
    fn write_u8(&mut self, value: &u8) -> Result<usize>;
    fn write_u16(&mut self, value: &u16) -> Result<usize>;
    fn write_u32(&mut self, value: &u32) -> Result<usize>;
}

pub struct CoffWriter<W: Write> {
    writer: W,
    pos: usize,
}

impl<W: Write> CoffWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn incr_pos(&mut self, n: usize) -> Result<usize> {
        self.pos += n;
        Ok(n)
    }

    pub fn write_bytes(&mut self, chars: &[u8]) -> Result<usize> {
        self.writer.write(chars).and_then(|n| self.incr_pos(n))
    }

    pub fn write_i16(&mut self, value: i16) -> Result<usize> {
        self.writer
            .write(&value.to_le_bytes())
            .and_then(|n| self.incr_pos(n))
    }

    pub fn write_i32(&mut self, value: i32) -> Result<usize> {
        self.writer
            .write(&value.to_le_bytes())
            .and_then(|n| self.incr_pos(n))
    }

    pub fn write_u8(&mut self, value: u8) -> Result<usize> {
        self.writer.write(&[value]).and_then(|n| self.incr_pos(n))
    }

    pub fn write_u16(&mut self, value: u16) -> Result<usize> {
        self.writer
            .write(&value.to_le_bytes())
            .and_then(|n| self.incr_pos(n))
    }

    pub fn write_u32(&mut self, value: u32) -> Result<usize> {
        self.writer
            .write(&value.to_le_bytes())
            .and_then(|n| self.incr_pos(n))
    }
}
