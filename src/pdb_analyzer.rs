use anyhow::{Context, Result};
use indicatif::{MultiProgress, ParallelProgressIterator, ProgressBar, ProgressStyle};
use pdb::{FallibleIterator, PDB, SymbolData};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

use crate::mmap_source::MmapSource;
use crate::pe_loader::{ControlFlowGraph, PeLoader};
use crate::warp::{Constraint, FunctionCall};
use crate::{DebugContext, compute_warp_uuid};

pub struct PdbAnalyzer {
    pe_loader: PeLoader,
    pdb: PDB<'static, MmapSource>,
    exe_name: String,
}

#[derive(Default, Debug, Clone)]
pub struct FunctionGuid {
    pub name: String,
    pub address: u64,
    pub size: Option<u32>,
    pub guid: Uuid,
    pub constraints: Vec<Constraint>,
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
            .with_context(|| format!("Failed to memory-map PDB file: {pdb_path:?}"))?;

        let pdb = PDB::open(mmap_source)
            .with_context(|| format!("Failed to parse PDB file: {pdb_path:?}"))?;

        let exe_name = exe_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(Self {
            pe_loader,
            pdb,
            exe_name,
        })
    }

    pub fn compute_function_guids_with_progress(
        &mut self,
        debug_context: &DebugContext,
        progress_bar: Option<MultiProgress>,
    ) -> Result<Vec<FunctionGuid>> {
        let address_map = self.pdb.address_map()?;

        // Create progress bar for collection phase
        let collection_pb = ProgressBar::new_spinner().with_style(
            ProgressStyle::default_spinner()
                .template(&format!(
                    "{{spinner:.green}} [{{elapsed_precise}}] Collecting procedures from PDB for {}...",
                    self.exe_name
                ))
                .unwrap(),
        );
        collection_pb.enable_steady_tick(std::time::Duration::from_millis(100));
        if let Some(multi) = &progress_bar {
            multi.insert_from_back(1, collection_pb.clone());
        };

        let mut procedures = Vec::new();

        // Collect all procedures in a single pass
        // Collect global symbols
        let symbol_table = self.pdb.global_symbols()?;
        let mut symbols = symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            if let Ok(SymbolData::Procedure(proc)) = symbol.parse()
                && let Some(rva) = proc.offset.to_rva(&address_map)
            {
                procedures.push(ProcedureData {
                    name: proc.name.to_string().to_string(),
                    rva: rva.0,
                    len: proc.len,
                });
            }
        }

        // Collect all modules first
        let dbi = self.pdb.debug_information()?;
        let mut modules_vec = Vec::new();
        let mut modules = dbi.modules()?;
        while let Some(module) = modules.next()? {
            if let Ok(Some(module_info)) = self.pdb.module_info(&module) {
                modules_vec.push(module_info);
            }
        }

        // Process modules in parallel to collect their symbols
        let module_procedures: Vec<Vec<ProcedureData>> = modules_vec
            .par_iter()
            .filter_map(|module_info| {
                let mut module_procs = Vec::new();
                if let Ok(mut module_symbols) = module_info.symbols() {
                    while let Ok(Some(symbol)) = module_symbols.next() {
                        if let Ok(SymbolData::Procedure(proc)) = symbol.parse()
                            && let Some(rva) = proc.offset.to_rva(&address_map)
                        {
                            module_procs.push(ProcedureData {
                                name: proc.name.to_string().to_string(),
                                rva: rva.0,
                                len: proc.len,
                            });
                        }
                    }
                }
                Some(module_procs)
            })
            .collect();

        // Extend procedures with all module procedures
        for module_procs in module_procedures {
            procedures.extend(module_procs);
        }

        // Now create/update progress bar for analysis phase
        let pb = ProgressBar::new(procedures.len() as u64).with_style(
                        ProgressStyle::default_bar()
                            .template(&format!("{{spinner:.green}} [{{elapsed_precise}}] [{{bar:40.cyan/blue}}] {{pos}}/{{len}} ({{per_sec}}, {{eta}}) {}", self.exe_name))
                            .expect("Failed to set progress style")
                            .progress_chars("#>-"));
        if let Some(multi) = &progress_bar {
            collection_pb.disable_steady_tick();
            multi.remove(&collection_pb);
            multi.insert_from_back(1, pb.clone());
        }

        // Create thread-safe references
        let pe_loader = &self.pe_loader;

        // Process procedures in parallel
        let (mut functions, calls): (HashMap<u64, FunctionGuid>, Vec<(u64, Vec<FunctionCall>)>) =
            procedures
                .par_iter()
                .progress_with(pb.clone())
                .filter_map(|proc_data| {
                    let address = proc_data.rva as u64 + pe_loader.image_base;

                    let mut cfg = ControlFlowGraph::default();
                    let size = match pe_loader.find_function_size_with_cfg(
                        address,
                        debug_context,
                        Some(&mut cfg),
                    ) {
                        Ok(sz) => Some(sz as u32),
                        Err(_) => None,
                    };

                    if let Some(size) = size {
                        match Self::compute_function_guid_static(
                            pe_loader,
                            address,
                            size as usize,
                            debug_context,
                            &cfg,
                        ) {
                            Ok((guid, calls)) => Some((
                                (
                                    address,
                                    FunctionGuid {
                                        name: proc_data.name.clone(),
                                        address,
                                        size: Some(size),
                                        guid,
                                        constraints: vec![],
                                    },
                                ),
                                (address, calls),
                            )),
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
                    }
                })
                .unzip();

        if let Some(multi) = progress_bar {
            pb.finish_and_clear();
            multi.remove(&pb);
        }

        // TODO analyze and calls to functions that have not already been found?
        // FIXME actually omitting calls leaves room for false positives so really should be fixed
        //
        // FIXME constraint GUID calculation is wrong (is not just function GUID)

        for (address, calls) in calls {
            let constraints = calls
                .into_iter()
                .flat_map(|call| {
                    Some(Constraint {
                        guid: functions.get(&call.target)?.guid,
                        offset: Some(call.offset as i64),
                    })
                })
                .collect();
            functions.get_mut(&address).unwrap().constraints = constraints;
        }

        Ok(functions.into_values().collect())
    }

    fn compute_function_guid_static(
        pe_loader: &PeLoader,
        address: u64,
        size: usize,
        debug_context: &DebugContext,
        cfg: &ControlFlowGraph,
    ) -> Result<(Uuid, Vec<FunctionCall>)> {
        let function_bytes = pe_loader.read_at_va(address, size)?;
        let mut calls = vec![];
        let guid = compute_warp_uuid(
            function_bytes,
            address,
            Some(&mut calls),
            debug_context,
            cfg,
        );
        Ok((guid, calls))
    }
}
