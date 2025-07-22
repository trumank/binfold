use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use pdb::{FallibleIterator, PDB, SymbolData};
use std::path::Path;
use uuid::Uuid;

use crate::mmap_source::MmapSource;
use crate::pe_loader::PeLoader;
use crate::{DebugContext, compute_warp_uuid};

pub struct PdbAnalyzer {
    pe_loader: PeLoader,
    pdb: PDB<'static, MmapSource>,
}

#[derive(Debug)]
pub struct FunctionGuid {
    pub name: String,
    pub address: u64,
    pub size: Option<u32>,
    pub guid: Uuid,
}

impl PdbAnalyzer {
    pub fn new(exe_path: &Path, pdb_path: &Path) -> Result<Self> {
        let pe_loader = PeLoader::load(exe_path)?;

        let mmap_source = MmapSource::new(pdb_path)
            .with_context(|| format!("Failed to memory-map PDB file: {:?}", pdb_path))?;

        let pdb = PDB::open(mmap_source)
            .with_context(|| format!("Failed to parse PDB file: {:?}", pdb_path))?;

        Ok(Self { pe_loader, pdb })
    }

    pub fn compute_function_guids(
        &mut self,
        debug_context: &DebugContext,
    ) -> Result<Vec<FunctionGuid>> {
        self.compute_function_guids_with_progress(debug_context, None)
    }

    pub fn compute_function_guids_with_progress(
        &mut self,
        debug_context: &DebugContext,
        progress_bar: Option<ProgressBar>,
    ) -> Result<Vec<FunctionGuid>> {
        let mut results = Vec::new();
        let address_map = self.pdb.address_map()?;

        // First, count total procedures for progress bar
        let mut total_procedures = 0;

        // Count global symbols
        let symbol_table = self.pdb.global_symbols()?;
        let mut symbols = symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            if let Ok(SymbolData::Procedure(_)) = symbol.parse() {
                total_procedures += 1;
            }
        }

        // Count module symbols
        let dbi = self.pdb.debug_information()?;
        let mut modules = dbi.modules()?;
        while let Some(module) = modules.next()? {
            if let Some(module_info) = self.pdb.module_info(&module)? {
                let mut module_symbols = module_info.symbols()?;
                while let Some(symbol) = module_symbols.next()? {
                    if let Ok(SymbolData::Procedure(_)) = symbol.parse() {
                        total_procedures += 1;
                    }
                }
            }
        }

        // Use provided progress bar or create a new one
        let pb = match progress_bar {
            Some(pb) => {
                pb.set_length(total_procedures as u64);
                pb
            }
            None => {
                let pb = ProgressBar::new(total_procedures as u64);
                pb.set_style(
                    ProgressStyle::default_bar()
                        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, {eta}) Analyzing functions")
                        .expect("Failed to set progress style")
                        .progress_chars("#>-")
                );
                pb
            }
        };

        // Process global symbols
        let symbol_table = self.pdb.global_symbols()?;
        let mut symbols = symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            if let Ok(SymbolData::Procedure(proc)) = symbol.parse() {
                self.process_procedure(&proc, &address_map, debug_context, &mut results);
                pb.inc(1);
            }
        }

        // Process module symbols
        let dbi = self.pdb.debug_information()?;
        let mut modules = dbi.modules()?;
        while let Some(module) = modules.next()? {
            if let Some(module_info) = self.pdb.module_info(&module)? {
                let mut module_symbols = module_info.symbols()?;
                while let Some(symbol) = module_symbols.next()? {
                    if let Ok(SymbolData::Procedure(proc)) = symbol.parse() {
                        self.process_procedure(&proc, &address_map, debug_context, &mut results);
                        pb.inc(1);
                    }
                }
            }
        }

        pb.finish_with_message("Analysis complete!");

        Ok(results)
    }

    fn process_procedure(
        &self,
        proc: &pdb::ProcedureSymbol,
        address_map: &pdb::AddressMap,
        debug_context: &DebugContext,
        results: &mut Vec<FunctionGuid>,
    ) {
        let name = proc.name.to_string().to_string();

        if let Some(rva) = proc.offset.to_rva(address_map) {
            let address = rva.0 as u64 + self.pe_loader.image_base;

            let size = if proc.len > 0 {
                Some(proc.len)
            } else {
                match self.pe_loader.find_function_size(address, debug_context) {
                    Ok(sz) => Some(sz as u32),
                    Err(_) => None,
                }
            };

            if let Some(size) = size {
                match self.compute_function_guid(address, size as usize, debug_context) {
                    Ok(guid) => {
                        results.push(FunctionGuid {
                            name: name.clone(),
                            address,
                            size: Some(size),
                            guid,
                        });
                    }
                    Err(e) => {
                        if debug_context.debug_guid {
                            eprintln!(
                                "Failed to compute GUID for function {} at 0x{:x}: {}",
                                name, address, e
                            );
                        }
                    }
                }
            }
        }
    }

    fn compute_function_guid(
        &self,
        address: u64,
        size: usize,
        debug_context: &DebugContext,
    ) -> Result<Uuid> {
        let function_bytes = self.pe_loader.read_at_va(address, size)?;

        let guid = compute_warp_uuid(&function_bytes, address, debug_context);

        Ok(guid)
    }
}
