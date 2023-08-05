#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, Write};
use std::path::PathBuf;
use std::{fs, process};

use clap::Parser;
use elf::abi::{EM_386, SHN_XINDEX, SHT_NULL, SHT_REL, SHT_STRTAB, SHT_SYMTAB, SHT_SYMTAB_SHNDX};
use elf::endian::LittleEndian;
use elf::ElfStream;
use simplelog::{LevelFilter, TermLogger};
use tempfile::NamedTempFile;

use crate::coff_go32::{Coff, CoffSectionType};

mod binfmt;
mod coff_go32;

/// ELF section types that should not be automatically copied to the resulting COFF
pub const IGNORE_ELF_SECTION_TYPES: [u32; 5] = [
    SHT_NULL,         // Don't need this for COFF
    SHT_SYMTAB,       // Symbols are processed separately
    SHT_STRTAB,       // We build our own string table
    SHT_SYMTAB_SHNDX, // Only used to look up large ELF section indices
    SHT_REL,          // We process relocations after sections and symbols
];

/// Pairs of section name prefixes and the corresponding COFF section type
pub const ELF_SECTION_TYPE_PREFIXES: [(&str, CoffSectionType); 6] = [
    (".text", CoffSectionType::Text),
    (".data", CoffSectionType::Data),
    (".rodata", CoffSectionType::Data),
    (".bss", CoffSectionType::Bss),
    (".debug", CoffSectionType::Unknown),
    (".note.GNU-stack", CoffSectionType::Unknown),
];

/// Section name prefix for relocation sections.  Should be followed by the section name that
/// the relocations are for.
pub const REL_PREFIX: &str = ".rel";

type SectionNumberForSymbolIdx = Vec<usize>;

pub struct ElfSectionToProcess {
    section_header: elf::section::SectionHeader,
    section_type: CoffSectionType,
    elf_index: usize,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    input_obj: PathBuf,
    output_obj: Option<PathBuf>,

    #[arg(short = 'i', long = "in-place")]
    in_place: bool,

    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
}

fn main() {
    let args = Args::parse();
    set_log_level(if args.quiet {
        LevelFilter::Warn
    } else {
        LevelFilter::Info
    });

    if args.in_place && args.output_obj.is_some() {
        error!("--in-place and OUTPUT_OBJ are mutually exclusive");
        process::exit(1);
    }
    if !args.in_place && args.output_obj.is_none() {
        error!("One of OUTPUT_OBJ or --in-place is required");
        process::exit(1);
    }

    let mut binary = load_elf(&args.input_obj);
    let coff = convert(&mut binary);

    let (outf, tmp_path) = output_file(&args.output_obj);
    let mut writer = BufWriter::new(outf);
    coff.write(&mut binary, &mut writer).unwrap_or_else(|e| {
        error!("Failed to write output file: {e}");
        process::exit(1);
    });
    writer.flush().expect("Failed to flush output buffer");

    if let Some(tmp_path) = tmp_path {
        fs::rename(&tmp_path, &args.input_obj).unwrap_or_else(|e| {
            error!(
                "Failed to overwrite {}: {e}",
                args.input_obj.to_string_lossy()
            );
            process::exit(1);
        });
        info!("Updated {}", args.input_obj.to_string_lossy());
    } else {
        info!(
            "Converted {} to {}",
            args.input_obj.to_string_lossy(),
            args.output_obj.unwrap().to_string_lossy()
        );
    }
}

fn set_log_level(level: LevelFilter) {
    TermLogger::init(
        level,
        simplelog::ConfigBuilder::new()
            .set_time_level(LevelFilter::Off)
            .build(),
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )
    .expect("Failed to initialize logger");
}

fn load_elf(path: &PathBuf) -> ElfStream<LittleEndian, File> {
    let inf = File::open(path).unwrap_or_else(|e| {
        error!("Could not open {}: {e}", path.to_string_lossy());
        process::exit(1);
    });
    let binary = ElfStream::<LittleEndian, _>::open_stream(inf).unwrap_or_else(|e| {
        error!("Could not parse {} as ELF: {e}", path.to_string_lossy());
        process::exit(1);
    });
    if binary.ehdr.e_machine != EM_386 {
        error!("Input file machine type mut be i386.");
        process::exit(1);
    }
    binary
}

fn output_file(path: &Option<PathBuf>) -> (File, Option<PathBuf>) {
    match path {
        Some(path) => {
            let f = File::create(path).unwrap_or_else(|e| {
                error!("Could not open output file {}: {e}", path.to_string_lossy());
                process::exit(1);
            });
            (f, None)
        }
        None => match NamedTempFile::new().map(NamedTempFile::keep) {
            Err(e) => {
                error!("Could not open temporary output file: {e}");
                process::exit(1);
            }
            Ok(Err(e)) => {
                error!("Could not open temporary output file: {e}");
                process::exit(1);
            }
            Ok(Ok((f, path))) => (f, Some(path)),
        },
    }
}

fn convert<S: Read + Seek>(mut binary: &mut ElfStream<LittleEndian, S>) -> Coff {
    let mut coff = Coff::new();

    // Add all the sections
    let sections = get_elf_sections_to_process(&mut binary);
    for section in sections.values() {
        coff.add_elf_section(
            binary,
            &section.section_header,
            section.elf_index,
            section.section_type,
        );
    }

    // Add all the symbols
    {
        let section_numbers = get_section_number_for_symbol_indexes(binary);
        let (symtab, strtab) = binary
            .symbol_table()
            .expect("Failed to parse symbol table")
            .expect("Missing symbol table");
        for (elf_symbol_idx, symbol) in symtab.iter().enumerate() {
            coff.add_elf_symbol(symbol, elf_symbol_idx, &strtab, &section_numbers);
        }
    }

    // Add all the relocations
    for (name, sh) in get_elf_rel_sections(binary) {
        // Find the section the relocations are for by name (.rel<section name>)
        if !name.starts_with(REL_PREFIX) {
            warn!("Ignoring relocation section {name:?} not prefixed by {REL_PREFIX:?}");
            continue;
        }
        let target_name = &name[REL_PREFIX.len()..];
        let target_section = sections.get(target_name);
        if target_section.is_none() {
            warn!(
                "Ignoring relocation section {name:?} with no corresponding {target_name:?} section"
            );
            continue;
        }
        let target_section = target_section.unwrap();

        // Parse the relocations and add them to the target section
        let rels = binary
            .section_data_as_rels(&sh)
            .unwrap_or_else(|_| panic!("Failed to parse section {name:?} as relocation data"));
        for rel in rels {
            coff.add_relocation(rel, target_section.elf_index);
        }

        // Sort the rels by address, since we'll be processing them as we copy the data
        coff.section_for_elf_index
            .get(&target_section.elf_index)
            .unwrap()
            .borrow_mut()
            .relocations
            .sort_by_key(|r| r.address);
    }
    coff
}

fn get_elf_sections_to_process<S: Read + Seek>(
    binary: &mut ElfStream<LittleEndian, S>,
) -> HashMap<String, ElfSectionToProcess> {
    let (section_headers, maybe_strtab) = binary
        .section_headers_with_strtab()
        .expect("Failed to read symbol table");
    let strtab = maybe_strtab.expect("No string table found");
    section_headers
        .iter()
        .enumerate()
        .filter_map(|(elf_index, sh)| {
            if IGNORE_ELF_SECTION_TYPES.contains(&sh.sh_type) {
                return None;
            }
            // Determine the COFF section type by name prefix
            let name = strtab.get(sh.sh_name as usize).unwrap();
            let section_type = ELF_SECTION_TYPE_PREFIXES
                .iter()
                .find(|(prefix, _)| name.starts_with(prefix))
                .map(|(_, st)| st)
                .copied()
                .unwrap_or_else(|| {
                    warn!(
                        "including unknown section {name} ({}) as non-text/data/bss",
                        sh.sh_type
                    );
                    CoffSectionType::Unknown
                });
            Some((
                name.to_string(),
                ElfSectionToProcess {
                    section_header: *sh,
                    section_type,
                    elf_index,
                },
            ))
        })
        .collect()
}

/// Parse the extended section indexes section (SHT_SYMTAB_SHNDX) if it exists.
fn get_elf_extended_section_indexes<S: Read + Seek>(
    binary: &mut ElfStream<LittleEndian, S>,
) -> Option<Vec<u32>> {
    for section in binary.section_headers().clone() {
        if section.sh_type == SHT_SYMTAB_SHNDX {
            let (data, compression) = binary
                .section_data(&section)
                .expect("Failed to read section SHT_SYMTAB_SHNDX");
            if compression.is_some() {
                panic!("Unexpected compression found for section SHT_SYMTAB_SHNDX");
            }
            #[cfg(target_endian = "little")]
            {
                return Some(bytemuck::cast_slice::<_, u32>(data).to_vec());
            }
            #[cfg(target_endian = "big")]
            {
                let mut result = bytemuck::cast_slice::<_, u32>(data).to_vec();
                for i in 0..result.len() {
                    result[i] = u32::from_le(result[i]);
                }
                return Some(result);
            }
        }
    }
    None
}

/// Return an array of section indexes corresponding to the symbol table entry at that index.
/// Extended section numbers (SHN_XINDEX) will be looked up from the SHT_SYMTAB_SHNDX section.
pub fn get_section_number_for_symbol_indexes<S: Read + Seek>(
    binary: &mut ElfStream<LittleEndian, S>,
) -> SectionNumberForSymbolIdx {
    let ext_section_indexes = get_elf_extended_section_indexes(binary);

    let (elf_symbol_table, _) = binary
        .symbol_table()
        .expect("Failed to parse symbol table")
        .expect("Missing symbol table");
    let mut result = Vec::with_capacity(elf_symbol_table.len());

    for (symbol_idx, symbol) in elf_symbol_table.iter().enumerate() {
        if symbol.st_shndx != SHN_XINDEX {
            // Normal section index
            result.push(symbol.st_shndx as usize)
        } else {
            // Extended section index
            match &ext_section_indexes {
                None => panic!("Symbol {symbol_idx} has section SHN_XINDEX, but no SHT_SYMTAB_SHNDX section exists"),
                Some(esi) => {
                    if let Some(section_idx) = esi.get(symbol_idx) {
                        result.push(*section_idx as usize);
                    } else {
                        panic!("SHT_SYMTAB_SHNDX section missing entry for symbol {symbol_idx}")
                    }
                }
            }
        }
    }
    result
}

pub fn get_elf_rel_sections<S: Read + Seek>(
    binary: &mut ElfStream<LittleEndian, S>,
) -> Vec<(String, elf::section::SectionHeader)> {
    let (section_headers, strtab) = binary.section_headers_with_strtab().unwrap();
    let strtab = strtab.unwrap();
    section_headers
        .iter()
        .filter_map(|sh| match sh.sh_type {
            SHT_REL => Some((
                strtab.get(sh.sh_name as usize).unwrap().to_owned(),
                sh.clone(),
            )),
            _ => None,
        })
        .collect()
}
