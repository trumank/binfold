//! Binfold library for binary function analysis and matching
//!
//! This library provides programmatic access to the WARP algorithm
//! for function identification and database-driven symbol matching.

use anyhow::Result;
use dashmap::{DashMap, DashSet};
use rayon::prelude::*;
use rustc_hash::FxBuildHasher;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

mod mmap_source;

pub mod db;
pub mod hash;
pub mod pdb_analyzer;
pub mod pdb_writer;
pub mod pe_loader;
pub mod progress;
pub mod warp;

// Re-export key types for convenience
pub use anyhow;
pub use uuid::Uuid;

// Re-export progress types
pub use progress::{NoOpProgressReporter, ProgressReporter, default_progress_style};

use crate::db::{
    BinaryGuid, ConstraintGuid, Db, DbHash, FunctionGuid, Layer, StringRef, SymbolGuid,
};
use crate::pdb_analyzer::PdbAnalyzer;
use crate::pdb_writer::{extract_pdb_info, generate_pdb};
use crate::pe_loader::{AnalysisCache, PeLoader};
use crate::warp::{Constraint, compute_function_guid_with_contraints};

/// High-level analyzer for binary function analysis
pub struct BinfoldAnalyzer {
    pe: PeLoader,
    db_mmap: Option<memmap2::Mmap>,
}

/// Options for analysis
pub struct AnalysisOptions<P: ProgressReporter = NoOpProgressReporter> {
    pub database_path: Option<PathBuf>,
    pub progress_reporter: P,
}

impl Default for AnalysisOptions<NoOpProgressReporter> {
    fn default() -> Self {
        Self {
            database_path: None,
            progress_reporter: NoOpProgressReporter,
        }
    }
}

impl<P: ProgressReporter> AnalysisOptions<P> {
    pub fn with_progress_reporter<P2: ProgressReporter>(self, reporter: P2) -> AnalysisOptions<P2> {
        AnalysisOptions {
            database_path: self.database_path,
            progress_reporter: reporter,
        }
    }
}

/// Result of function analysis
pub struct AnalysisResult {
    pub functions: Vec<AnalyzedFunction>,
    pub database_matches: HashMap<u64, MatchInfo>,
}

/// Analyzed function with computed GUID and constraints
pub struct AnalyzedFunction {
    pub address: u64,
    pub size: u64,
    pub guid: FunctionGuid,
    pub constraints: Vec<Constraint<DbHash>>,
}

/// Information about database matching
#[derive(Debug, Clone)]
pub struct MatchInfo {
    pub symbol_name: Option<String>,
    pub matched_constraints: usize,
    pub total_constraints: usize,
}

impl BinfoldAnalyzer {
    /// Create analyzer for the given executable
    pub fn new<P: AsRef<Path>>(exe_path: P) -> Result<Self> {
        let pe = PeLoader::load(exe_path.as_ref())?;
        Ok(Self { pe, db_mmap: None })
    }

    /// Create analyzer with database for symbol matching
    pub fn with_database<P1, P2>(exe_path: P1, db_path: P2) -> Result<Self>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        let pe = PeLoader::load(exe_path.as_ref())?;
        let file = std::fs::File::open(db_path.as_ref())?;
        let db_mmap = Some(unsafe { memmap2::MmapOptions::new().map(&file)? });
        Ok(Self { pe, db_mmap })
    }

    /// Analyze all functions in the binary with progress reporting
    pub fn analyze_with_progress<P: ProgressReporter>(
        &self,
        progress_reporter: &P,
    ) -> Result<AnalysisResult> {
        let functions = self.pe.find_all_functions()?;
        let cache = AnalysisCache::new(functions.iter().cloned());

        let analyzed: HashSet<u64> = functions.iter().map(|f| f.entry_point).collect();

        let mut analyzed_functions = Vec::new();
        let mut function_guids = HashSet::new();

        // Use parallel processing for GUID computation like main.rs
        let guid_progress = progress_reporter.sub_progress("Computing function GUIDs".into());
        guid_progress.initialize(analyzed.len() as u64);

        let results = analyzed
            .par_iter()
            .copied()
            .map(|addr| {
                let result = (
                    addr,
                    compute_function_guid_with_contraints::<DbHash>(&self.pe, &cache, addr),
                );
                guid_progress.progress();
                result
            })
            .collect::<Vec<(u64, Result<_>)>>();
        guid_progress.finish();

        for (_addr, result) in results {
            match result {
                Ok(warp_func) => {
                    function_guids.insert(warp_func.guid);
                    analyzed_functions.push(AnalyzedFunction {
                        address: warp_func.address,
                        size: warp_func.size as u64,
                        guid: warp_func.guid,
                        constraints: warp_func.constraints,
                    });
                }
                Err(_) => continue, // Skip failed analyses
            }
        }
        analyzed_functions.sort_by_key(|f| f.address);

        // Add parent call constraints
        let mut callers: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
        let mut functions_by_addr: HashMap<u64, FunctionGuid> = HashMap::new();

        for func in &analyzed_functions {
            functions_by_addr.insert(func.address, func.guid);
            for call in &cache.get(func.address, &self.pe).unwrap().calls {
                callers
                    .entry(call.target)
                    .or_default()
                    .push((func.address, (call.address - func.address)));
            }
        }

        // Add parent constraints to functions
        for func in &mut analyzed_functions {
            if let Some(parent_calls) = callers.get(&func.address) {
                for (parent_addr, offset) in parent_calls {
                    if let Some(parent_guid) = functions_by_addr.get(parent_addr) {
                        func.constraints.push(Constraint {
                            guid: ConstraintGuid::from_parent_call(*parent_guid),
                            offset: Some(*offset as i64),
                        });
                    }
                }
            }
        }

        // Database matching if available
        let database_matches = if let Some(mmap) = &self.db_mmap {
            self.match_with_database(
                &analyzed_functions,
                &function_guids,
                &cache,
                mmap,
                progress_reporter,
            )?
        } else {
            HashMap::new()
        };

        Ok(AnalysisResult {
            functions: analyzed_functions,
            database_matches,
        })
    }

    /// Analyze all functions in the binary
    pub fn analyze(&self) -> Result<AnalysisResult> {
        self.analyze_with_progress(&NoOpProgressReporter)
    }

    /// Generate PDB file with matched symbols
    pub fn generate_pdb<P: AsRef<Path>>(
        &self,
        result: &AnalysisResult,
        output_path: P,
    ) -> Result<()> {
        let pdb_info = extract_pdb_info(&self.pe)?;

        let pdb_functions: Vec<_> = result
            .functions
            .iter()
            .filter_map(|f| {
                result
                    .database_matches
                    .get(&f.address)
                    .and_then(|m| m.symbol_name.as_ref())
                    .map(|name| pdb_writer::FunctionInfo {
                        address: f.address,
                        size: f.size as u32,
                        name: name.clone(),
                    })
            })
            .collect();

        generate_pdb(&self.pe, &pdb_info, &pdb_functions, output_path.as_ref())?;
        Ok(())
    }

    /// Get the PE loader for direct access
    pub fn pe_loader(&self) -> &PeLoader {
        &self.pe
    }

    // Private helper extracted from existing main.rs logic
    fn match_with_database<P: ProgressReporter>(
        &self,
        analyzed_functions: &[AnalyzedFunction],
        function_guids: &HashSet<FunctionGuid>,
        cache: &AnalysisCache,
        mmap: &memmap2::Mmap,
        progress_reporter: &P,
    ) -> Result<HashMap<u64, MatchInfo>> {
        let db = Db::new(mmap)?;

        // Build cache of unique constraints with parallel processing
        let load_progress = progress_reporter.sub_progress("Loading database constraints".into());
        load_progress.initialize(function_guids.len() as u64);

        let cache_unique_constraints: HashMap<
            FunctionGuid,
            HashMap<ConstraintGuid, HashSet<StringRef>>,
        > = function_guids
            .par_iter()
            .map(|guid| {
                let mut by_constraint: HashMap<ConstraintGuid, HashSet<StringRef>> = HashMap::new();
                for c in db.iter_constraints(guid) {
                    by_constraint
                        .entry(*c.guid())
                        .or_default()
                        .extend(c.iter_symbols());
                }
                load_progress.progress();
                (*guid, by_constraint)
            })
            .collect();
        load_progress.finish();

        // Build callers map
        let mut callers: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
        let mut functions_by_addr: HashMap<u64, FunctionGuid> = HashMap::new();

        for func in analyzed_functions {
            functions_by_addr.insert(func.address, func.guid);
            for call in &cache.get(func.address, &self.pe).unwrap().calls {
                callers
                    .entry(call.target)
                    .or_default()
                    .push((func.address, (call.address - func.address)));
            }
        }

        let mut matched_functions: HashMap<u64, MatchInfo> = HashMap::new();
        let mut unmatched_functions: HashMap<u64, &AnalyzedFunction> =
            analyzed_functions.iter().map(|f| (f.address, f)).collect();

        // Iterative matching loop
        loop {
            let mut new_matches: Vec<u64> = Vec::new();

            let match_progress = progress_reporter.sub_progress("Matching functions".into());
            match_progress.initialize(unmatched_functions.len() as u64);

            for func in unmatched_functions.values() {
                // Add symbol-based constraints for already matched functions
                let mut constraints = func.constraints.clone();

                // Check if any of our calls have been matched - add symbol constraints
                for call in &cache.get(func.address, &self.pe).unwrap().calls {
                    if let Some(unique_name) = matched_functions
                        .get(&call.target)
                        .and_then(|m| m.symbol_name.as_deref())
                    {
                        let target_symbol = SymbolGuid::from_symbol(unique_name);
                        constraints.push(Constraint {
                            guid: ConstraintGuid::from_symbol_child_call(target_symbol),
                            offset: Some((call.address - func.address) as i64),
                        });
                    }
                }

                // Check if any functions that call us have been matched - add symbol parent constraints
                if let Some(parent_calls) = callers.get(&func.address) {
                    for (parent_addr, offset) in parent_calls {
                        if let Some(unique_name) = matched_functions
                            .get(parent_addr)
                            .and_then(|m| m.symbol_name.as_deref())
                        {
                            let parent_symbol = SymbolGuid::from_symbol(unique_name);
                            constraints.push(Constraint {
                                guid: ConstraintGuid::from_symbol_parent_call(parent_symbol),
                                offset: Some(*offset as i64),
                            });
                        }
                    }
                }

                // Try to match with constraints
                let db_constraints = cache_unique_constraints.get(&func.guid).unwrap();

                let query_constraints: HashSet<ConstraintGuid> =
                    constraints.iter().map(|c| c.guid).collect();

                let mut unique_name = [ConstraintGuid::nil()]
                    .iter()
                    .chain(query_constraints.iter())
                    .find_map(|c| {
                        if let Some(matches) = db_constraints.get(c)
                            && matches.len() == 1
                        {
                            matches.iter().next().copied()
                        } else {
                            None
                        }
                    });

                // Count how many constraints matched
                let matched_count = query_constraints
                    .iter()
                    .filter(|c| db_constraints.contains_key(c))
                    .count();

                if unique_name.is_none() {
                    let mut sorted_constraints: Vec<_> = query_constraints
                        .iter()
                        .filter_map(|guid| db_constraints.get(guid))
                        .collect();
                    sorted_constraints.sort_by_key(|c| c.len());

                    fn find_unique<'a>(
                        first: &HashSet<StringRef<'a>>,
                        rest: &[&HashSet<StringRef<'a>>],
                    ) -> Option<StringRef<'a>> {
                        let mut possible = None;
                        for item in first {
                            if rest.iter().all(|r| r.contains(item)) {
                                if possible.is_some() {
                                    possible = None;
                                    break;
                                } else {
                                    possible = Some(*item);
                                }
                            }
                        }
                        possible
                    }

                    if let Some((first, rest)) = sorted_constraints.split_first()
                        && !rest.is_empty()
                    {
                        unique_name = find_unique(first, rest);
                    }
                }

                if unique_name.is_some() {
                    new_matches.push(func.address);
                }

                matched_functions.insert(
                    func.address,
                    MatchInfo {
                        symbol_name: unique_name
                            .map(|n| n.as_str().map(|s| s.to_string()))
                            .transpose()?,
                        matched_constraints: matched_count,
                        total_constraints: constraints.len(),
                    },
                );

                match_progress.progress();
            }

            match_progress.finish();

            // If no new matches found, we're done
            if new_matches.is_empty() {
                break;
            }

            // Remove new matches from unmatched list
            for addr in &new_matches {
                unmatched_functions.remove(addr);
            }
        }

        Ok(matched_functions)
    }
}

/// Builder for creating function databases
pub struct DatabaseBuilder {
    exe_paths: Vec<PathBuf>,
    parallel: usize,
}

impl DatabaseBuilder {
    pub fn new() -> Self {
        Self {
            exe_paths: Vec::new(),
            parallel: std::thread::available_parallelism()
                .map(|n| n.get() / 2)
                .unwrap_or(1)
                .max(1),
        }
    }

    /// Cap on the number of executables loaded into memory simultaneously
    /// during gen-db. Each in-flight producer holds an mmap'd exe + PDB plus a
    /// working `HashMap<u64, FunctionInfo>`, so this is the main knob for peak
    /// memory.
    pub fn parallel(&mut self, n: usize) -> &mut Self {
        self.parallel = n.max(1);
        self
    }

    pub fn add_executable<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.exe_paths.push(path.as_ref().to_path_buf());
        self
    }

    pub fn add_directory<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        for entry in walkdir::WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if entry.file_type().is_file()
                && let Some(ext) = path.extension()
                && ext.eq_ignore_ascii_case("exe")
            {
                let pdb_path = path.with_extension("pdb");
                if pdb_path.exists() {
                    self.exe_paths.push(path.to_path_buf());
                }
            }
        }
        self
    }

    pub fn build<P: AsRef<Path>>(&self, output_path: P) -> Result<DatabaseStats> {
        self.build_with_progress(output_path, &NoOpProgressReporter)
    }

    pub fn build_with_progress<P: AsRef<Path>, PR: ProgressReporter>(
        &self,
        output_path: P,
        progress_reporter: &PR,
    ) -> Result<DatabaseStats> {
        use std::fs;
        use std::io::BufWriter;

        if self.exe_paths.is_empty() {
            anyhow::bail!("No EXE files specified");
        }

        // Append a new layer if a database already exists at the output path;
        // otherwise create a fresh one. Snapshot the existing DB's known
        // binary hashes so workers can skip anything already present.
        let (append, known_binaries): (bool, HashSet<BinaryGuid>) =
            match fs::File::open(output_path.as_ref()) {
                Ok(existing_file) => {
                    let mmap = unsafe { memmap2::MmapOptions::new().map(&existing_file)? };
                    (true, Db::new(&mmap)?.all_binaries())
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, HashSet::new()),
                Err(e) => return Err(e.into()),
            };

        let op = progress_reporter.sub_progress("Processing executables".into());
        op.initialize(self.exe_paths.len() as u64);

        // Concurrent merge state. Everything is a flat (func_id, constraint_id,
        // symbol_id) triple in a single DashSet - incremental dedup with no
        // per-(func, constraint) HashSet allocations. Func and constraint GUID
        // interners assign u32 IDs via DashMap + AtomicU32. The string interner
        // stays under one Mutex so the (vec, map) pair stays in lockstep.
        struct Interner {
            strings: Vec<String>,
            string_to_index: HashMap<String, u32>,
        }
        let interner: Mutex<Interner> = Mutex::new(Interner {
            strings: Vec::new(),
            string_to_index: HashMap::new(),
        });
        let func_ids: DashMap<FunctionGuid, u32, FxBuildHasher> =
            DashMap::with_hasher(FxBuildHasher);
        let constraint_ids: DashMap<ConstraintGuid, u32, FxBuildHasher> =
            DashMap::with_hasher(FxBuildHasher);
        let func_counter = AtomicU32::new(0);
        let constraint_counter = AtomicU32::new(0);
        let triples: DashSet<(u32, u32, u32), FxBuildHasher> = DashSet::with_hasher(FxBuildHasher);

        // Pre-intern the nil constraint so we can reference its ID without an
        // extra atomic on the hot path.
        let nil_constraint_id = *constraint_ids
            .entry(ConstraintGuid::nil())
            .or_insert_with(|| constraint_counter.fetch_add(1, Ordering::Relaxed));

        let intern_string = |name: String| -> u32 {
            let mut i = interner.lock().unwrap();
            if let Some(&idx) = i.string_to_index.get(&name) {
                return idx;
            }
            let idx: u32 = i.strings.len().try_into().expect("symbol count > u32");
            i.string_to_index.insert(name.clone(), idx);
            i.strings.push(name);
            idx
        };

        let merge_func =
            |guid: FunctionGuid,
             name_id: u32,
             constraint_guids: &mut dyn Iterator<Item = ConstraintGuid>| {
                let func_id = *func_ids
                    .entry(guid)
                    .or_insert_with(|| func_counter.fetch_add(1, Ordering::Relaxed));
                triples.insert((func_id, nil_constraint_id, name_id));
                for cg in constraint_guids {
                    let c_id = *constraint_ids
                        .entry(cg)
                        .or_insert_with(|| constraint_counter.fetch_add(1, Ordering::Relaxed));
                    triples.insert((func_id, c_id, name_id));
                }
            };

        let exe_paths = &self.exe_paths;
        let known_binaries_ref = &known_binaries;
        let cursor = std::sync::atomic::AtomicUsize::new(0);
        let op_ref = &op;
        let processed_binaries: Mutex<Vec<BinaryGuid>> = Mutex::new(Vec::new());
        let processed_binaries_ref = &processed_binaries;

        let process = |exe_path: &PathBuf| {
            let pdb_path_for_exe = exe_path.with_extension("pdb");

            let result = (|| -> Result<Option<BinaryGuid>> {
                // Hash from the same mmap PdbAnalyzer will use - both the hash
                // and PE parse share one disk read.
                let pe = PeLoader::load(exe_path)?;
                let guid = BinaryGuid::from_bytes(pe.raw_bytes());
                if known_binaries_ref.contains(&guid) {
                    return Ok(None);
                }
                let mut analyzer = PdbAnalyzer::from_pe_loader(pe, &pdb_path_for_exe)?;
                let exe_name = exe_path
                    .file_name()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_else(|| "<unknown>".into());
                let sub_progress = op_ref.sub_progress(format!("Processing {}", exe_name).into());

                // Stream each FunctionInfo straight into the merge - never
                // materializes a full Vec, so producer peak is just the
                // analyzer's working HashMap.
                analyzer.process_function_guids_with_progress(
                    Some(sub_progress),
                    |f: pdb_analyzer::FunctionInfo| {
                        let name_id = intern_string(f.name);
                        merge_func(
                            f.guid,
                            name_id,
                            &mut f.constraints.into_iter().map(|c| c.guid),
                        );
                    },
                )?;
                Ok(Some(guid))
            })();

            match result {
                Ok(Some(guid)) => processed_binaries_ref.lock().unwrap().push(guid),
                Ok(None) => {}
                Err(e) => eprintln!("Error processing {}: {}", exe_path.display(), e),
            }

            op_ref.progress();
        };

        let parallel = self.parallel.min(exe_paths.len());
        rayon::scope(|s| {
            for _ in 0..parallel {
                s.spawn(|_| {
                    loop {
                        let i = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if i >= exe_paths.len() {
                            break;
                        }
                        process(&exe_paths[i]);
                    }
                });
            }
        });
        op.finish();
        let mut processed_binaries = processed_binaries.into_inner().unwrap();
        processed_binaries.sort_unstable();

        let strings = interner.into_inner().unwrap().strings;

        // Build constraint_guids[]: indexed by interner-assigned ID.
        let constraint_count = constraint_counter.load(Ordering::Relaxed) as usize;
        let mut constraint_guids = vec![ConstraintGuid::nil(); constraint_count];
        for entry in constraint_ids.iter() {
            constraint_guids[*entry.value() as usize] = *entry.key();
        }
        drop(constraint_ids);

        // Build function_guids[] sorted by GUID, plus a remap table from
        // interner ID -> sorted index.
        let func_count = func_counter.load(Ordering::Relaxed) as usize;
        let mut func_pairs: Vec<(FunctionGuid, u32)> =
            func_ids.iter().map(|e| (*e.key(), *e.value())).collect();
        drop(func_ids);
        func_pairs.sort_unstable_by_key(|&(g, _)| g);
        let mut func_remap = vec![0u32; func_count];
        for (new_id, &(_, old_id)) in func_pairs.iter().enumerate() {
            func_remap[old_id as usize] = new_id as u32;
        }
        let function_guids: Vec<FunctionGuid> = func_pairs.into_iter().map(|(g, _)| g).collect();

        // Drain triples into a flat Vec, remap func_ids, and sort.
        let mut triples_vec: Vec<(u32, u32, u32)> = triples.into_iter().collect();
        for t in &mut triples_vec {
            t.0 = func_remap[t.0 as usize];
        }
        drop(func_remap);
        triples_vec.par_sort_unstable();

        // Count (func, constraint) pairs whose symbol set is exactly one - a
        // group of identical (f, c) prefix-tuples of length 1 in the sorted
        // triples.
        let unique_constraints: usize = {
            let mut count = 0usize;
            let mut i = 0;
            while i < triples_vec.len() {
                let (f, c, _) = triples_vec[i];
                let mut j = i + 1;
                while j < triples_vec.len() && triples_vec[j].0 == f && triples_vec[j].1 == c {
                    j += 1;
                }
                if j - i == 1 {
                    count += 1;
                }
                i = j;
            }
            count
        };

        let total_functions = function_guids.len();

        {
            let layer = Layer {
                strings: &strings,
                constraint_guids: &constraint_guids,
                function_guids: &function_guids,
                triples: &triples_vec,
                binaries: &processed_binaries,
            };
            if append {
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(output_path.as_ref())?;
                db::append_layer(&mut file, &layer)?;
            } else {
                let file = fs::File::create(output_path.as_ref())?;
                let mut writer = BufWriter::new(file);
                db::write_database(&[&layer], &mut writer)?;
            }
        }

        Ok(DatabaseStats {
            total_functions,
            unique_constraints,
            processed_files: processed_binaries.len(),
        })
    }
}

impl Default for DatabaseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics from database creation
pub struct DatabaseStats {
    pub total_functions: usize,
    pub unique_constraints: usize,
    pub processed_files: usize,
}
