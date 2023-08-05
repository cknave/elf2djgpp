use crate::binfmt::{
    CoffFileHeader, CoffRelocation, CoffSectionHeader, CoffSerialize, CoffSymbol, CoffWriter,
};
use crate::SectionNumberForSymbolIdx;
use bitflags::bitflags;
use elf::abi::{STB_GLOBAL, STB_LOCAL, STT_FILE, STT_FUNC, STT_NOTYPE, STT_OBJECT};
use elf::endian::LittleEndian;
use elf::ElfStream;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek, Write};
use std::rc::Rc;

/// Maximum size of short section/symbol names
pub const MAX_NAME_LEN: usize = 8;

/// Offset the beginning of the string table to skip over the uint32 that precedes it
pub const STRING_TABLE_BASE_OFFSET: usize = 4;

// The rust-elf library is missing i386 relocation type constants but that's cool, I'll just copy
// them from this Oracle doc???  Why is this the only reference I can find?
// https://docs.oracle.com/cd/E19683-01/817-3677/chapter6-26/index.html
pub const R_386_32: u32 = 1;
pub const R_386_PC32: u32 = 2;
pub const R_386_PLT32: u32 = 4;
pub const R_386_GOTOFF: u32 = 9;
pub const R_386_GOTPC: u32 = 10;

/// A compiler-builtins bug (or cargo bug?) causes these undefined symbols to end up in the
/// resulting library: https://github.com/rust-lang/compiler-builtins/issues/347
///
/// Link them to the real DJGPP functions instead by renaming the symbols, what could possibly go
/// wrong
const FIX_EXTERN_SYMBOLS_PREFIXES: [(&str, &[u8]); 6] = [
    ("compiler_builtins::mem::memset", b"memset"),
    ("compiler_builtins::mem::memcmp", b"memcmp"),
    ("compiler_builtins::mem::bcmp", b"bcmp"),
    ("compiler_builtins::mem::strlen", b"strlen"),
    ("compiler_builtins::mem::memcpy", b"memcpy"),
    ("compiler_builtins::mem::memmove", b"memmove"),
];

pub fn fix_extern_symbol(name: Cow<[u8]>) -> Cow<[u8]> {
    // Only attempt to demangle strings we can decode
    let str_name = match std::str::from_utf8(&name) {
        Err(_) => return name,
        Ok(s) => rustc_demangle::demangle(s).to_string(),
    };
    for (prefix, replacement) in FIX_EXTERN_SYMBOLS_PREFIXES {
        if str_name.starts_with(prefix) {
            warn!(
                "Replacing bad extern {str_name} with {}",
                String::from_utf8_lossy(replacement)
            );
            return Cow::from(replacement);
        }
    }
    return name;
}

/// Helper to get the string table from an ElfStream, assuming it exists.  We have to do this in
/// every new scope because borrow checker.
fn get_strtab<S: Read + Seek>(
    binary: &mut ElfStream<LittleEndian, S>,
) -> elf::string_table::StringTable {
    let (_, maybe_strtab) = binary.section_headers_with_strtab().unwrap();
    maybe_strtab.unwrap()
}

pub struct Coff {
    pub sections: Vec<Rc<RefCell<Section>>>,
    pub symbols: Vec<Rc<RefCell<Symbol>>>,
    pub strings: StringTable,
    pub section_for_elf_index: BTreeMap<usize, Rc<RefCell<Section>>>,
    pub section_for_elf_section_name: HashMap<Vec<u8>, Rc<RefCell<Section>>>,
    pub symbol_for_elf_symbol_index: BTreeMap<usize, Rc<RefCell<Symbol>>>,
}

impl Coff {
    pub fn new() -> Self {
        Self {
            sections: vec![],
            symbols: vec![],
            strings: StringTable::new(),
            section_for_elf_index: BTreeMap::new(),
            section_for_elf_section_name: HashMap::new(),
            symbol_for_elf_symbol_index: BTreeMap::new(),
        }
    }

    pub fn add_elf_section<S: Read + Seek>(
        &mut self,
        binary: &mut ElfStream<LittleEndian, S>,
        elf_section: &elf::section::SectionHeader,
        elf_section_index: usize,
        section_type: CoffSectionType,
    ) -> Rc<RefCell<Section>> {
        // Get the section name, optionally storing in our string table if it's too large
        let elf_strtab = get_strtab(binary);
        let section_name = elf_strtab
            .get_raw(elf_section.sh_name as usize)
            .expect("No name found for section {section_index}");
        let name = if section_name.len() > MAX_NAME_LEN {
            let offset = self.strings.add(section_name);
            Name::StringTableIndex(offset)
        } else {
            Name::from_slice(section_name)
        };

        let section_number = CoffSectionNumber::Index((self.sections.len() + 1) as i16); // section numbers are 1-based
        let section = Rc::new(RefCell::new(Section {
            name,
            section_type,
            elf_section_index,
            number: section_number,
            address: elf_section.sh_addr as u32,
            size: elf_section.sh_size as u32,
            relocations: vec![],
        }));
        self.sections.push(section.clone());
        self.section_for_elf_index
            .insert(elf_section_index, section.clone());
        if self.section_for_elf_section_name.contains_key(section_name) {
            panic!(
                "Attempted to add section {0:?} twice",
                String::from_utf8_lossy(section_name)
            );
        }
        self.section_for_elf_section_name
            .insert(section_name.to_vec(), section.clone());
        section
    }

    pub fn add_elf_symbol(
        &mut self,
        elf_symbol: elf::symbol::Symbol,
        elf_symbol_index: usize,
        elf_strtab: &elf::string_table::StringTable,
        elf_section_numbers: &SectionNumberForSymbolIdx,
    ) -> Option<Rc<RefCell<Symbol>>> {
        let name: Name;
        let section_number: CoffSectionNumber;
        let storage_class: SymbolStorageClass;

        let elf_section_index = elf_section_numbers[elf_symbol_index];
        if elf_symbol.st_symtype() == elf::abi::STT_SECTION {
            // Special case: section symbols
            let section = self.section_for_elf_index[&elf_section_index].borrow();
            name = section.name;
            section_number = section.number;
            storage_class = SymbolStorageClass::Static;
        } else {
            // Normal case: every other kind of symbol
            let strtab_ent = elf_strtab
                .get_raw(elf_symbol.st_name as usize)
                .unwrap_or_else(|_| {
                    panic!(
                        "No name found for symbol {elf_symbol_index} (st_name {0})",
                        elf_symbol.st_name
                    )
                });
            name = self.process_symbol_name(&elf_symbol, strtab_ent);
            storage_class = SymbolStorageClass::for_elf_symbol(&elf_symbol);
            if self.strings.get_name(&name).is_empty() && elf_symbol.st_symtype() == STT_NOTYPE {
                // COFF doesn't like this empty symbol, skip it
                return None;
            } else if elf_symbol.st_symtype() == STT_FILE {
                section_number = CoffSectionNumber::Debugging;
            } else if elf_symbol.is_undefined() {
                section_number = CoffSectionNumber::Extern;
            } else if let Some(section) = self.section_for_elf_index.get(&elf_section_index) {
                section_number = section.borrow().number;
            } else {
                warn!(
                    "Skipping symbol {} from skipped section",
                    String::from_utf8_lossy(strtab_ent)
                );
                return None;
            }
        }

        let symbol = Rc::new(RefCell::new(Symbol {
            name,
            value: elf_symbol.st_value as u32,
            section_number,
            storage_class,
            index: self.symbols.len(),
        }));
        self.symbol_for_elf_symbol_index
            .insert(elf_symbol_index, symbol.clone());
        self.symbols.push(symbol.clone());
        return Some(symbol);
    }

    pub fn add_relocation(
        &mut self,
        elf_relocation: elf::relocation::Rel,
        elf_section_index: usize,
    ) {
        let symbol = self
            .symbol_for_elf_symbol_index
            .get(&(elf_relocation.r_sym as usize))
            .unwrap();
        let relocation_type = match elf_relocation.r_type {
            // The i386 ABI appears to be the same as the x86_64 ABI for these reloc types
            R_386_PC32 | R_386_PLT32 => CoffRelocationType::Relative,
            R_386_32 => CoffRelocationType::Absolute,
            R_386_GOTOFF => panic!(
                "Unsupported relocation type R_386_GOTOFF: try compiling with\
                -fno-pic"
            ),
            R_386_GOTPC => panic!(
                "Unsupported relocation type R_386_GOTPC: try compiling with\
                -fno-pic"
            ),
            _ => panic!("Unknown relocation type {}", elf_relocation.r_type),
        };
        let section = self.section_for_elf_index.get(&elf_section_index).unwrap();
        section.borrow_mut().relocations.push(Relocation {
            address: elf_relocation.r_offset as u32,
            symbol: symbol.clone(),
            relocation_type,
        });
    }

    pub fn write<S: Read + Seek, T: Write>(
        &self,
        binary: &mut ElfStream<LittleEndian, S>,
        output: &mut T,
    ) -> std::io::Result<()> {
        let mut writer = CoffWriter::new(output);

        // Keep track of where the data for each section will start, beginning after the headers
        let mut data_offset =
            (CoffFileHeader::SIZE + CoffSectionHeader::SIZE * self.sections.len()) as u32;

        // Write the COFF headers
        let file_header = CoffFileHeader::from_coff(self);
        file_header.serialize(&mut writer)?;
        let mut expected_section_offsets = Vec::<usize>::with_capacity(self.sections.len());
        for section in &self.sections {
            let section = section.borrow();
            let section_header = CoffSectionHeader::from_section(&section, data_offset);
            section_header.serialize(&mut writer)?;
            expected_section_offsets.push(data_offset as usize);
            if section.section_type != CoffSectionType::Bss {
                // BSS sections are not stored in the file
                data_offset += section.size;
            }
            data_offset += (CoffRelocation::SIZE * section.relocations.len()) as u32;
            // TODO: lineno offset
        }

        // Write the data, relocs, and line numbers for each section
        let elf_sections = binary.section_headers().clone();
        for (i, section) in self.sections.iter().enumerate() {
            assert_eq!(expected_section_offsets[i], writer.pos());
            let section = section.borrow();
            let elf_sh = elf_sections.get(section.elf_section_index).unwrap();
            let (data, compression) = binary.section_data(elf_sh).unwrap_or_else(|_| {
                let name = self.strings.get_name(&section.name);
                panic!("Failed to parse section {name:?}");
            });
            if compression.is_some() {
                let name = self.strings.get_name(&section.name);
                panic!("Unexpected compression header for section {name:?}");
            }

            // Fix the data for relative relocations.
            // In our clang ELF binaries, the target operand points to its *own address* relative
            // to the section start.
            // But in our DJGPP binaries, the target operand points to the section start.
            // So for relocation to work properly, we need to fix all those addresses to point to
            // the section start.
            let mut copy_ofs: usize = 0;
            for reloc in &section.relocations {
                if reloc.relocation_type == CoffRelocationType::Relative {
                    writer.write_bytes(&data[copy_ofs..reloc.address as usize])?;
                    copy_ofs = reloc.address as usize + 4;
                    let rel_to_start = -(copy_ofs as i32);
                    writer.write_i32(rel_to_start)?;
                }
            }
            writer.write_bytes(&data[copy_ofs..])?;

            // Now we can write the relocations themselves
            for reloc in &section.relocations {
                let reloc_data = CoffRelocation::from_relocation(reloc);
                reloc_data.serialize(&mut writer)?;
            }
        }

        // Write the symbol table after all the sections
        for symbol in &self.symbols {
            let symbol_data = CoffSymbol::from_symbol(&symbol.borrow());
            symbol_data.serialize(&mut writer)?;
        }

        // Write the string table length as a u32 before dumping all the strings
        writer.write_u32((self.strings.contents.len() + STRING_TABLE_BASE_OFFSET) as u32)?;
        writer.write_bytes(self.strings.contents.as_slice())?;

        Ok(())
    }

    /// Return a Name for this symbol and its ELF string table entry, possibly adding it to our
    /// own string table.
    fn process_symbol_name(&mut self, elf_symbol: &elf::symbol::Symbol, strtab_ent: &[u8]) -> Name {
        let mut raw_name = Cow::from(strtab_ent);

        // If it's empty, there's nothing further to process
        if raw_name.is_empty() {
            return Name::from_slice(raw_name.as_ref());
        }

        // Deal with nonexistent compiler-builtins symbols
        if elf_symbol.is_undefined() {
            raw_name = fix_extern_symbol(raw_name);
        }

        // Add the DJGPP underscore prefix if needed
        if elf_symbol.is_undefined()
            || elf_symbol.st_symtype() == STT_FUNC
            || elf_symbol.st_symtype() == STT_OBJECT
        {
            let mut prefixed = Vec::with_capacity(raw_name.len() + 1);
            prefixed.push(b'_');
            prefixed.extend(raw_name.as_ref());
            raw_name = Cow::from(prefixed);
        }

        // Add to the string table if too long
        if raw_name.len() > MAX_NAME_LEN {
            let strtab_ofs = self.strings.add(raw_name.as_ref());
            return Name::StringTableIndex(strtab_ofs);
        }

        // Otherwise return a literal copied from the raw name
        Name::from_slice(raw_name.as_ref())
    }
}

pub struct Section {
    pub name: Name,
    pub section_type: CoffSectionType,
    pub number: CoffSectionNumber,
    pub address: u32,
    pub size: u32,
    pub relocations: Vec<Relocation>,
    pub elf_section_index: usize,
}

impl Section {
    pub fn size_on_disk(&self) -> u32 {
        match self.section_type {
            CoffSectionType::Bss => 0, // BSS sections are not stored on disk
            _ => self.size,
        }
    }
}

#[derive(Copy, Clone)]
pub enum Name {
    Literal([u8; MAX_NAME_LEN]),
    StringTableIndex(StringTableIndex),
}

impl Name {
    pub fn from_slice(s: &[u8]) -> Self {
        assert!(s.len() <= MAX_NAME_LEN);
        let mut l = [0; MAX_NAME_LEN];
        l[..s.len()].clone_from_slice(s);
        Self::Literal(l)
    }
}

type StringTableIndex = u32;
type StringTableOffset = u32;

#[repr(u16)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CoffSectionType {
    Unknown = 0,
    Text = 0x0020,
    Data = 0x0040,
    Bss = 0x0080,
}

pub struct Relocation {
    pub address: u32,
    pub symbol: Rc<RefCell<Symbol>>,
    pub relocation_type: CoffRelocationType,
}

pub struct Symbol {
    pub name: Name,
    pub value: u32,
    pub section_number: CoffSectionNumber,
    pub storage_class: SymbolStorageClass,
    pub index: usize,
}

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum SymbolStorageClass {
    External = 2, // globals and externs
    Static = 3,   // section names
    Label = 6,    // local code
    FileName = 103,
}

impl SymbolStorageClass {
    pub fn for_elf_symbol(elf_symbol: &elf::symbol::Symbol) -> Self {
        match (elf_symbol.st_symtype(), elf_symbol.st_bind()) {
            (STT_FILE, _) => Self::FileName,
            (STT_FUNC, STB_LOCAL) => Self::Label,
            (_, STB_GLOBAL) => Self::External,
            _ => Self::Static,
        }
    }
}

#[repr(u16)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CoffRelocationType {
    Absolute = 0x0006,
    Relative = 0x0014,
}

pub struct StringTable {
    pub contents: Vec<u8>,
    pub string_offsets: HashMap<Vec<u8>, StringTableOffset>,
}

impl StringTable {
    pub fn new() -> Self {
        Self {
            contents: vec![],
            string_offsets: Default::default(),
        }
    }

    pub fn add(&mut self, s: &[u8]) -> StringTableOffset {
        let index = (self.contents.len() + STRING_TABLE_BASE_OFFSET) as StringTableOffset;
        self.contents.extend(s.iter());
        self.contents.push(0);
        self.string_offsets.insert(s.to_vec(), index);
        index
    }

    pub fn get_string(&self, offset: StringTableOffset) -> &[u8] {
        let offset_to_end = &self.contents[offset as usize..];
        if let Some(end) = offset_to_end.iter().position(|&c| c == 0) {
            &offset_to_end[..end]
        } else {
            offset_to_end
        }
    }

    pub fn get_name(&self, name: &Name) -> Cow<[u8]> {
        match name {
            Name::Literal(s) => Cow::Owned(s.iter().cloned().take_while(|c| *c != b'\0').collect()),
            Name::StringTableIndex(idx) => Cow::Borrowed(self.get_string(*idx)),
        }
    }
}

#[derive(Copy, Clone)]
pub enum CoffSectionNumber {
    Extern,
    Debugging,
    Index(i16),
}

impl CoffSectionNumber {
    pub fn bits(&self) -> i16 {
        match self {
            CoffSectionNumber::Extern => 0,
            CoffSectionNumber::Debugging => -2,
            CoffSectionNumber::Index(value) => *value,
        }
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct CoffFileFlags: u16 {
        const RelocsStripped = 0b0001;
        const Executable = 0b0010;
        const LineNumsStripped = 0b0100;
        const LocalSymsStripped = 0b1000;
        const Machine32BitLittleEndian = 0x0100;
    }
}
