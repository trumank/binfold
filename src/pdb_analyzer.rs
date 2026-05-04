use anyhow::{Context, Result};
use pdb::{FallibleIterator, PDB, SymbolData};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;

use crate::db::{ConstraintGuid, DbHash, FunctionGuid, SymbolGuid};
use crate::mmap_source::MmapSource;
use crate::pe_loader::PeLoader;
use crate::warp::{Constraint, compute_function_guid_with_contraints};
use crate::{AnalysisCache, NoOpProgressReporter, ProgressReporter};

pub struct PdbAnalyzer {
    pe_loader: PeLoader,
    pdb: PDB<'static, MmapSource>,
}

#[derive(Default, Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub size: Option<u32>,
    pub guid: FunctionGuid,
    pub constraints: Vec<Constraint<DbHash>>,
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

        Ok(Self { pe_loader, pdb })
    }

    pub fn compute_function_guids(&mut self) -> Result<Vec<FunctionInfo>> {
        let mut out = Vec::new();
        self.process_function_guids_with_progress::<NoOpProgressReporter, _>(None, |f| {
            out.push(f)
        })?;
        Ok(out)
    }

    pub fn compute_function_guids_with_progress<P: ProgressReporter>(
        &mut self,
        progress_reporter: Option<P>,
    ) -> Result<Vec<FunctionInfo>> {
        let mut out = Vec::new();
        self.process_function_guids_with_progress(progress_reporter, |f| out.push(f))?;
        Ok(out)
    }

    /// Run the full GUID + constraint pipeline and stream each FunctionInfo to
    /// `emit` as it's finalized. Avoids holding both the working HashMap and a
    /// returned Vec at peak - caller-side merging happens in lockstep so each
    /// FunctionInfo is dropped right after it's consumed.
    pub fn process_function_guids_with_progress<P, F>(
        &mut self,
        progress_reporter: Option<P>,
        mut emit: F,
    ) -> Result<()>
    where
        P: ProgressReporter,
        F: FnMut(FunctionInfo),
    {
        let address_map = self.pdb.address_map()?;
        let image_base = self.pe_loader.image_base();

        // Pass 1: walk the global symbol stream once to collect public function
        // symbols. The public stream carries the canonical mangled name (with
        // full type signature), which we prefer over the bare textual proc name
        // from the module stream when both exist.
        let mut publics: HashMap<u64, String> = HashMap::new();
        {
            let global_symbols = self.pdb.global_symbols()?;
            let mut iter = global_symbols.iter();
            while let Ok(Some(symbol)) = iter.next() {
                if let Ok(SymbolData::Public(p)) = symbol.parse()
                    && p.function
                    && let Some(rva) = p.offset.to_rva(&address_map)
                {
                    // First-wins on collisions (ICF/COMDAT can fold multiple
                    // publics to the same RVA).
                    publics
                        .entry(image_base + rva.0 as u64)
                        .or_insert_with(|| p.name.to_string().into_owned());
                }
            }
        }

        // Pass 2: collect module procedures (textual qualified names + len).
        let dbi = self.pdb.debug_information()?;
        let mut modules = dbi.modules()?;
        let mut module_infos = Vec::new();
        while let Some(module) = modules.next()? {
            if let Ok(Some(module_info)) = self.pdb.module_info(&module) {
                module_infos.push(module_info);
            }
        }

        let procedures: Vec<_> = module_infos
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
                    acc.entry(item.rva as u64 + image_base)
                        .or_default()
                        .push(item);
                    acc
                });

        let cache = AnalysisCache::default();

        if let Some(reporter) = &progress_reporter {
            reporter.initialize(binned_procs.len() as u64);
        }

        // Process procedures in parallel.
        // FunctionInfo no longer carries `calls` - the constraint pass below
        // reads them straight from the AnalysisCache, avoiding a per-function
        // clone of the call list (which was a large chunk of producer heap).
        // TODO figure out how to handle multiple names for single address
        // TODO this processes each individual symbol and can do a lot of duplicate work if they share same address
        let mut functions: HashMap<u64, FunctionInfo> = binned_procs
            .par_iter()
            .map(|(&address, procs)| -> Result<_> {
                // TODO figure out what to do with the rest
                let proc = procs[0];

                let func = compute_function_guid_with_contraints::<DbHash>(
                    &self.pe_loader,
                    &cache,
                    address,
                )?;
                let analysis = cache.get(address, &self.pe_loader).unwrap();
                // Prefer the public mangled name when available (carries full
                // type signature). Fall back to the bare textual proc name for
                // file-static / synthetic functions that have no public.
                let name = publics
                    .get(&address)
                    .cloned()
                    .unwrap_or_else(|| proc.name.clone());
                let func_info = FunctionInfo {
                    name,
                    address,
                    size: Some(analysis.size as u32),
                    guid: func.guid,
                    constraints: func.constraints,
                };

                if let Some(reporter) = &progress_reporter {
                    reporter.progress();
                }

                Ok((address, func_info))
            })
            .collect::<Result<_>>()?;

        if let Some(reporter) = progress_reporter {
            reporter.finish();
        }

        // TODO analyze and calls to functions that have not already been found?
        // FIXME actually omitting calls leaves room for false positives so really should be fixed

        // Build a map of who calls whom for parent constraints (via cache).
        let mut callers: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
        for &caller_address in functions.keys() {
            let analysis = cache.get(caller_address, &self.pe_loader).unwrap();
            for call in &analysis.calls {
                callers
                    .entry(call.target)
                    .or_default()
                    .push((caller_address, call.address - caller_address));
            }
        }

        let constraints: Vec<_> = functions
            .par_iter()
            .map(|(address, _info)| {
                let mut constraints = Vec::new();
                let analysis = cache.get(*address, &self.pe_loader).unwrap();

                // Add child call constraints (symbol-based)
                for call in &analysis.calls {
                    if let Some(target_fn) = functions.get(&call.target) {
                        let offset = Some((call.address - address) as i64);
                        // Function-based child constraint already exists from warp analysis.
                        let target_symbol = SymbolGuid::from_symbol(&target_fn.name);
                        constraints.push(Constraint {
                            guid: ConstraintGuid::from_symbol_child_call(target_symbol),
                            offset,
                        });
                    }
                }

                // Add parent call constraints (function-based and symbol-based)
                if let Some(parent_calls) = callers.get(address) {
                    for (parent_addr, offset) in parent_calls {
                        if let Some(parent_fn) = functions.get(parent_addr) {
                            let offset = Some(*offset as i64);
                            constraints.push(Constraint {
                                guid: ConstraintGuid::from_parent_call(parent_fn.guid),
                                offset,
                            });
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

        // Cache + callers map are no longer needed; drop before the emit phase
        // so their heap (and the cache's Arc<FunctionAnalysis>s) is freed.
        drop(cache);
        drop(callers);

        for (address, c) in constraints {
            functions.get_mut(&address).unwrap().constraints.extend(c);
        }

        // Stream each FunctionInfo out so the caller can merge and drop it
        // before the next entry is produced. Avoids the duplicate Vec peak.
        for (_, info) in functions {
            emit(info);
        }

        Ok(())
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
