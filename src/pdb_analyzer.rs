use anyhow::{Context, Result};
use indicatif::{MultiProgress, ParallelProgressIterator, ProgressBar, ProgressStyle};
use pdb::{FallibleIterator, PDB, SymbolData};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use tracing::warn;

use crate::compute_warp_uuid;
use crate::mmap_source::MmapSource;
use crate::pe_loader::{ControlFlowGraph, PeLoader};
use crate::warp::{Constraint, ConstraintGuid, FunctionCall, FunctionGuid};

pub struct PdbAnalyzer {
    pe_loader: PeLoader,
    pdb: PDB<'static, MmapSource>,
    exe_name: String,
}

#[derive(Default, Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub size: Option<u32>,
    pub guid: FunctionGuid,
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
        progress_bar: Option<MultiProgress>,
    ) -> Result<Vec<FunctionInfo>> {
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
        let (mut functions, calls): (HashMap<u64, FunctionInfo>, Vec<(u64, Vec<FunctionCall>)>) =
            procedures
                .par_iter()
                .progress_with(pb.clone())
                .filter_map(|proc_data| {
                    let address = proc_data.rva as u64 + pe_loader.image_base;

                    let mut cfg = ControlFlowGraph::default();
                    let size = match pe_loader.find_function_size_with_cfg(address, Some(&mut cfg))
                    {
                        Ok(sz) => Some(sz as u32),
                        Err(_) => None,
                    };

                    if let Some(size) = size {
                        match Self::compute_function_guid_static(
                            pe_loader,
                            address,
                            size as usize,
                            &cfg,
                        ) {
                            Ok((guid, calls)) => Some((
                                (
                                    address,
                                    FunctionInfo {
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
                                warn!(
                                    target: "warp_testing::pdb_analyzer",
                                    function_name = %proc_data.name,
                                    address = format!("0x{:x}", address),
                                    error = %e,
                                    "Failed to compute GUID for function"
                                );
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

        // Build a map of who calls whom for parent constraints
        let mut callers: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
        for (caller_address, calls) in &calls {
            for call in calls {
                callers
                    .entry(call.target)
                    .or_default()
                    .push((*caller_address, call.offset));
            }
        }

        for (address, calls) in calls {
            let mut constraints = Vec::new();

            // Add child call constraints
            for call in calls {
                if let Some(target_fn) = functions.get(&call.target) {
                    constraints.push(Constraint {
                        guid: ConstraintGuid::from_child_call(target_fn.guid),
                        offset: Some(call.offset as i64),
                    });
                }
            }

            // Add parent call constraints
            if let Some(parent_calls) = callers.get(&address) {
                for (parent_addr, offset) in parent_calls {
                    if let Some(parent_fn) = functions.get(parent_addr) {
                        constraints.push(Constraint {
                            guid: ConstraintGuid::from_parent_call(parent_fn.guid),
                            offset: Some(*offset as i64),
                        });
                    }
                }
            }

            functions.get_mut(&address).unwrap().constraints = constraints;
        }

        Ok(functions.into_values().collect())
    }

    fn compute_function_guid_static(
        pe_loader: &PeLoader,
        address: u64,
        size: usize,
        cfg: &ControlFlowGraph,
    ) -> Result<(FunctionGuid, Vec<FunctionCall>)> {
        let function_bytes = pe_loader.read_at_va(address, size)?;
        let mut calls = vec![];
        let guid = compute_warp_uuid(function_bytes, address, Some(&mut calls), cfg);
        Ok((guid, calls))
    }
}
