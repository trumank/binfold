use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use pdb::{FallibleIterator, PDB, SymbolData};
use rayon::prelude::*;
use std::path::Path;
use std::sync::{Arc, Mutex};
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

// Structure to hold procedure data for parallel processing
#[derive(Clone)]
struct ProcedureData {
    name: String,
    rva: u32,
    len: u32,
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
        let address_map = self.pdb.address_map()?;

        // Create progress bar for collection phase
        let collection_pb = match &progress_bar {
            Some(pb) => {
                pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.green} [{elapsed_precise}] Collecting procedures from PDB...")
                        .expect("Failed to set progress style")
                );
                pb.clone()
            }
            None => {
                let pb = ProgressBar::new_spinner();
                pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.green} [{elapsed_precise}] Collecting procedures from PDB...")
                        .expect("Failed to set progress style")
                );
                pb.enable_steady_tick(std::time::Duration::from_millis(100));
                pb
            }
        };

        let mut procedures = Vec::new();

        // Collect all procedures in a single pass
        // Collect global symbols
        let symbol_table = self.pdb.global_symbols()?;
        let mut symbols = symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            if let Ok(SymbolData::Procedure(proc)) = symbol.parse() {
                if let Some(rva) = proc.offset.to_rva(&address_map) {
                    procedures.push(ProcedureData {
                        name: proc.name.to_string().to_string(),
                        rva: rva.0,
                        len: proc.len,
                    });
                    collection_pb.tick();
                }
            }
        }

        // Collect module symbols
        let dbi = self.pdb.debug_information()?;
        let mut modules = dbi.modules()?;
        while let Some(module) = modules.next()? {
            if let Some(module_info) = self.pdb.module_info(&module)? {
                let mut module_symbols = module_info.symbols()?;
                while let Some(symbol) = module_symbols.next()? {
                    if let Ok(SymbolData::Procedure(proc)) = symbol.parse() {
                        if let Some(rva) = proc.offset.to_rva(&address_map) {
                            procedures.push(ProcedureData {
                                name: proc.name.to_string().to_string(),
                                rva: rva.0,
                                len: proc.len,
                            });
                            collection_pb.tick();
                        }
                    }
                }
            }
        }

        let total_procedures = procedures.len();
        collection_pb.finish_and_clear();

        // Now create/update progress bar for analysis phase
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

        // Create thread-safe references
        let pe_loader = Arc::new(&self.pe_loader);
        let debug_context = Arc::new(debug_context);
        let progress_bar = Arc::new(Mutex::new(pb));

        // Process procedures in parallel
        let results: Vec<_> = procedures
            .par_iter()
            .filter_map(|proc_data| {
                let address = proc_data.rva as u64 + pe_loader.image_base;

                let size = if proc_data.len > 0 {
                    Some(proc_data.len)
                } else {
                    match pe_loader.find_function_size(address, &debug_context) {
                        Ok(sz) => Some(sz as u32),
                        Err(_) => None,
                    }
                };

                let result = if let Some(size) = size {
                    match Self::compute_function_guid_static(
                        &pe_loader,
                        address,
                        size as usize,
                        &debug_context,
                    ) {
                        Ok(guid) => Some(FunctionGuid {
                            name: proc_data.name.clone(),
                            address,
                            size: Some(size),
                            guid,
                        }),
                        Err(e) => {
                            if debug_context.debug_guid {
                                eprintln!(
                                    "Failed to compute GUID for function {} at 0x{:x}: {}",
                                    proc_data.name, address, e
                                );
                            }
                            None
                        }
                    }
                } else {
                    None
                };

                // Update progress bar
                if let Ok(pb) = progress_bar.lock() {
                    pb.inc(1);
                }

                result
            })
            .collect();

        if let Ok(pb) = progress_bar.lock() {
            pb.finish_and_clear();
        }

        Ok(results)
    }

    fn compute_function_guid_static(
        pe_loader: &PeLoader,
        address: u64,
        size: usize,
        debug_context: &DebugContext,
    ) -> Result<Uuid> {
        let function_bytes = pe_loader.read_at_va(address, size)?;
        let guid = compute_warp_uuid(&function_bytes, address, debug_context);
        Ok(guid)
    }
}
