use anyhow::{Context, Result};
use indicatif::{MultiProgress, ParallelProgressIterator, ProgressBar};
use pdb::{FallibleIterator, PDB, SymbolData};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;

use crate::mmap_source::MmapSource;
use crate::pe_loader::{FunctionCall, PeLoader};
use crate::warp::{
    Constraint, ConstraintGuid, FunctionGuid, SymbolGuid, compute_function_guid_with_contraints,
};
use crate::{AnalysisCache, progress_style};

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
    pub calls: Vec<FunctionCall>,
}

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

        enum SymbolsProducer<'a> {
            Global(pdb::SymbolTable<'a>),
            Module(pdb::ModuleInfo<'a>),
        }
        impl<'a> SymbolsProducer<'a> {
            fn symbols(&self) -> Result<pdb::SymbolIter<'_>, pdb::Error> {
                match self {
                    SymbolsProducer::Global(s) => Ok(s.iter()),
                    SymbolsProducer::Module(s) => s.symbols(),
                }
            }
        }

        // Collect global symbols
        let mut symbol_producers = vec![SymbolsProducer::Global(self.pdb.global_symbols()?)];

        // Collect modules
        let dbi = self.pdb.debug_information()?;
        let mut modules = dbi.modules()?;
        while let Some(module) = modules.next()? {
            if let Ok(Some(module_info)) = self.pdb.module_info(&module) {
                symbol_producers.push(SymbolsProducer::Module(module_info));
            }
        }

        let procedures: Vec<_> = symbol_producers
            .iter()
            .map(|module_info| {
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
                module_procs
            })
            .collect();

        let binned_procs: HashMap<u64, Vec<&ProcedureData>> =
            procedures
                .iter()
                .flatten()
                .fold(Default::default(), |mut acc, item| {
                    acc.entry(item.rva as u64 + self.pe_loader.image_base())
                        .or_default()
                        .push(item);
                    acc
                });

        // Now create/update progress bar for analysis phase
        let pb = ProgressBar::new(binned_procs.len() as u64)
            .with_style(progress_style())
            .with_message(self.exe_name.clone());
        if let Some(multi) = &progress_bar {
            multi.insert_from_back(2, pb.clone());
        }

        let cache = AnalysisCache::default();

        // Process procedures in parallel
        // TODO figure out how to handle multiple names for single address
        // TODO this processes each individual symbol and can do a lot of duplicate work if they share same address
        let mut functions: HashMap<u64, FunctionInfo> = binned_procs
            .par_iter()
            .progress_with(pb.clone())
            .map(|(&address, procs)| -> Result<_> {
                // TODO figure out what to do with the rest
                let proc = procs[0];

                let size = self.pe_loader.analyze_function(address)?.size;

                let func = compute_function_guid_with_contraints(&self.pe_loader, &cache, address)?;
                let analysis = cache.get(address, &self.pe_loader).unwrap();
                let func_info = FunctionInfo {
                    name: proc.name.clone(),
                    address,
                    size: Some(size as u32),
                    guid: func.guid,
                    constraints: func.constraints,
                    calls: analysis.calls.clone(),
                };
                Ok((address, func_info))
            })
            .collect::<Result<_>>()?;

        if let Some(multi) = progress_bar {
            pb.finish_and_clear();
            multi.remove(&pb);
        }

        // TODO analyze and calls to functions that have not already been found?
        // FIXME actually omitting calls leaves room for false positives so really should be fixed

        // Build a map of who calls whom for parent constraints
        let mut callers: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
        for (caller_address, info) in &functions {
            for call in &info.calls {
                callers
                    .entry(call.target)
                    .or_default()
                    .push((*caller_address, (call.address - *caller_address)));
            }
        }

        // TODO figure out if/why hashing is so slow (sha1_smol crate?) and cache/optimize
        let constraints: Vec<_> = functions
            .par_iter()
            .map(|(address, info)| {
                let mut constraints = Vec::new();

                // Add child call constraints (both function-based and symbol-based)
                for call in &info.calls {
                    if let Some(target_fn) = functions.get(&call.target) {
                        let offset = Some((call.address - address) as i64);
                        // Function-based child constraint
                        // (already exists from warp analysis)
                        // constraints.push(Constraint {
                        //     guid: ConstraintGuid::from_child_call(target_fn.guid),
                        //     offset,
                        // });

                        // Symbol-based child constraint
                        let target_symbol = SymbolGuid::from_symbol(&target_fn.name);
                        constraints.push(Constraint {
                            guid: ConstraintGuid::from_symbol_child_call(target_symbol),
                            offset,
                        });
                    }
                }

                // Add parent call constraints (both function-based and symbol-based)
                if let Some(parent_calls) = callers.get(address) {
                    for (parent_addr, offset) in parent_calls {
                        if let Some(parent_fn) = functions.get(parent_addr) {
                            let offset = Some(*offset as i64);
                            // Function-based parent constraint
                            constraints.push(Constraint {
                                guid: ConstraintGuid::from_parent_call(parent_fn.guid),
                                offset,
                            });

                            // Symbol-based parent constraint
                            let parent_symbol = SymbolGuid::from_symbol(&parent_fn.name);
                            constraints.push(Constraint {
                                guid: ConstraintGuid::from_symbol_parent_call(parent_symbol),
                                offset,
                            });
                        }
                    }
                }
                (*address, constraints)
            })
            .collect();
        for (address, constraints) in constraints {
            functions
                .get_mut(&address)
                .unwrap()
                .constraints
                .extend(constraints);
        }

        Ok(functions.into_values().collect())
    }
}

/// Check if a PDB file contains a global symbol with an EnvBlock containing "pdbgen_canary"
/// If so the PDB was generated by this tool and allow replacing
pub fn should_replace(pdb_path: &Path) -> Result<bool> {
    let mmap_source = MmapSource::new(pdb_path)
        .with_context(|| format!("Failed to memory-map PDB file: {pdb_path:?}"))?;

    let mut pdb = PDB::open(mmap_source)
        .with_context(|| format!("Failed to parse PDB file: {pdb_path:?}"))?;

    let global_symbols = pdb.global_symbols()?;
    let mut symbols = global_symbols.iter();

    while let Some(symbol) = symbols.next()? {
        if let Ok(SymbolData::EnvBlock(env_block)) = symbol.parse() {
            for entry in env_block.entries {
                if entry.to_string().contains("pdbgen_canary") {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}
