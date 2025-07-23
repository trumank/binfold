use anyhow::{Context, Result};
use pdb_sdk::{
    Guid,
    builders::{ModuleBuilder, PdbBuilder},
    codeview::{
        DataRegionOffset,
        symbols::{Procedure, ProcedureProperties, Public, PublicProperties, SymbolRecord},
        types::{CallingConvention, FunctionProperties, TypeRecord},
    },
    dbi::{SectionContrib, SectionHeader},
    utils::StrBuf,
};
use std::collections::HashMap;
use std::fs;
use std::io::BufWriter;
use std::path::Path;

use crate::pe_loader::PeLoader;

#[derive(Debug)]
pub struct PdbInfo {
    pub age: u32,
    pub timestamp: u32,
    pub guid: [u8; 16],
}

#[derive(Debug)]
pub struct FunctionInfo {
    pub address: u64,
    pub size: u32,
    pub name: String,
}

#[derive(Debug)]
struct SectionInfo {
    name: String,
    index: u16,
    virtual_address: u32,
    virtual_size: u32,
    characteristics: u32,
}

pub fn generate_pdb(
    pe: &PeLoader,
    pdb_info: &PdbInfo,
    functions: &[FunctionInfo],
    output_path: &Path,
) -> Result<()> {
    let mut builder = PdbBuilder::default();
    builder.info().guid(Guid(pdb_info.guid));
    builder.info().age(pdb_info.age);
    builder.info().signature(pdb_info.timestamp);

    let sections = build_sections(pe, &mut builder)?;
    build_functions(pe, &mut builder, &sections, functions)?;

    let output = BufWriter::new(fs::File::create(output_path)?);
    builder.commit(output)?;

    Ok(())
}

fn build_sections(pe: &PeLoader, builder: &mut PdbBuilder) -> Result<Vec<SectionInfo>> {
    let mut sections = Vec::new();

    for (idx, section) in pe.sections().enumerate() {
        let name = section.name()?;
        let mut name_array = [0u8; 8];
        let name_bytes = name.as_bytes();
        let len = name_bytes.len().min(8);
        name_array[..len].copy_from_slice(&name_bytes[..len]);

        let section_info = SectionInfo {
            name: name.to_string(),
            index: (idx as u16) + 1, // Section indices are 1-based in PDB
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
            characteristics: section.characteristics,
        };

        builder.dbi().add_section_header(SectionHeader {
            name: name_array,
            virtual_size: section.virtual_size,
            virtual_address: section.virtual_address,
            size_of_raw_data: section.size_of_raw_data,
            pointer_to_raw_data: section.pointer_to_raw_data,
            pointer_to_relocations: 0,
            pointer_to_line_numbers: 0,
            number_of_relocations: 0,
            number_of_line_numbers: 0,
            characteristics: section.characteristics,
        });

        sections.push(section_info);
    }

    Ok(sections)
}

fn build_functions(
    pe: &PeLoader,
    builder: &mut PdbBuilder,
    sections: &[SectionInfo],
    functions: &[FunctionInfo],
) -> Result<()> {
    // Create a simple void function type
    let void_fn_type = {
        let tpi = builder.tpi();

        let arg_list = tpi.add(
            "args",
            TypeRecord::ArgList {
                count: 0,
                arg_list: vec![],
            },
        );

        tpi.add(
            "void_func",
            TypeRecord::Procedure {
                return_type: None,
                calling_conv: CallingConvention::NearC,
                properties: FunctionProperties::new(),
                arg_count: 0,
                arg_list,
            },
        )
    };

    let base_address = pe.image_base();
    let mut functions_by_section: HashMap<u16, Vec<&FunctionInfo>> = HashMap::new();

    // Group functions by section
    for function in functions {
        for section in sections {
            let section_start = base_address + section.virtual_address as u64;
            let section_end = section_start + section.virtual_size as u64;

            if (section_start..section_end).contains(&function.address) {
                functions_by_section
                    .entry(section.index)
                    .or_default()
                    .push(function);
                break;
            }
        }
    }

    // Create modules for each section with functions
    for (section_idx, section_functions) in functions_by_section {
        let section = sections
            .iter()
            .find(|s| s.index == section_idx)
            .context("section not found")?;

        let section_start = base_address + section.virtual_address as u64;

        let sec_contrib = SectionContrib {
            i_sect: section_idx,
            pad1: [0, 0],
            offset: 0,
            size: section.virtual_size,
            characteristics: section.characteristics,
            i_mod: 0,
            pad2: [0, 0],
            data_crc: 0,
            reloc_crc: 0,
        };

        let mut module = ModuleBuilder::new(
            format!("{}_module", section.name),
            format!("/warp/{}.obj", section.name),
            sec_contrib,
        );

        // Add functions to module and public symbols
        for function in section_functions {
            let func_offset = (function.address - section_start) as u32;

            // Add to module
            let proc_idx = module.symbols.len();
            module.add_symbol(SymbolRecord::GlobalProc(Procedure {
                parent: None,
                end: 0.into(),
                next: None,
                code_size: function.size,
                dbg_start_offset: 0,
                dbg_end_offset: 0,
                function_type: void_fn_type,
                code_offset: DataRegionOffset::new(func_offset, section_idx),
                properties: ProcedureProperties::new(),
                name: StrBuf::new(format!("pdb_{}", function.name)),
            }));
            let end_idx = module.add_symbol(SymbolRecord::ProcEnd);
            match &mut module.symbols[proc_idx] {
                SymbolRecord::GlobalProc(proc) => proc.end = end_idx,
                _ => unreachable!(),
            }

            // Add to public symbols
            builder.dbi().symbols().add(Public {
                properties: PublicProperties::new().with_is_function(true),
                offset: DataRegionOffset::new(func_offset, section_idx),
                name: StrBuf::new(format!("pdb_{}", function.name)),
            });
        }

        builder.dbi().add_module(module);
    }

    Ok(())
}

pub fn extract_pdb_info(pe: &PeLoader) -> Result<PdbInfo> {
    // Get PDB info from the PE debug directory
    let pdb_debug_info = pe.pdb_info()?;

    Ok(PdbInfo {
        age: pdb_debug_info.age,
        timestamp: pe.timestamp()?,
        guid: pdb_debug_info.guid,
    })
}
