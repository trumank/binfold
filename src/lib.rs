//! Binfold library for binary function analysis and matching
//!
//! This library provides programmatic access to the WARP algorithm
//! for function identification and database-driven symbol matching.

use anyhow::Result;
use dashmap::DashMap;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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

use crate::db::{ConstraintGuid, Db, DbHash, DbWriter, FunctionGuid, StringRef, SymbolGuid};
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
                let result = (
                    *guid,
                    db.iter_constraints(guid)
                        .map(|c| (*c.guid(), c.iter_symbols().collect()))
                        .collect(),
                );
                load_progress.progress();
                result
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
        use std::fs;

        fn find_exe_files_recursive(
            dir: &Path,
            exe_files: &mut Vec<PathBuf>,
        ) -> std::io::Result<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_dir() {
                    let _ = find_exe_files_recursive(&path, exe_files);
                } else if let Some(ext) = path.extension()
                    && ext.eq_ignore_ascii_case("exe")
                {
                    let pdb_path = path.with_extension("pdb");
                    if pdb_path.exists() {
                        exe_files.push(path);
                    }
                }
            }
            Ok(())
        }

        let mut found_exe_paths = Vec::new();
        let _ = find_exe_files_recursive(path.as_ref(), &mut found_exe_paths);
        self.exe_paths.extend(found_exe_paths);
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

        let op = progress_reporter.sub_progress("Processing executables".into());
        op.initialize(self.exe_paths.len() as u64);

        // Concurrent merge state. Producers merge directly - no channel, no
        // dedicated merger thread. The DashMap shards by FunctionGuid so two
        // producers only contend if they touch the same shard at the same time.
        // String interning is one combined mutex (set + vec stay in lockstep).
        struct Interner {
            strings: Vec<String>,
            string_to_index: HashMap<String, u64>,
        }
        let interner: Mutex<Interner> = Mutex::new(Interner {
            strings: Vec::new(),
            string_to_index: HashMap::new(),
        });
        let constraint_to_names: DashMap<FunctionGuid, HashMap<ConstraintGuid, HashSet<u64>>> =
            DashMap::new();

        let intern = |name: String| -> u64 {
            let mut i = interner.lock().unwrap();
            if let Some(&idx) = i.string_to_index.get(&name) {
                return idx;
            }
            let idx = i.strings.len() as u64;
            i.string_to_index.insert(name.clone(), idx);
            i.strings.push(name);
            idx
        };

        let merge_func =
            |guid: FunctionGuid,
             name_id: u64,
             constraint_guids: &mut dyn Iterator<Item = ConstraintGuid>| {
                let mut entry = constraint_to_names.entry(guid).or_default();
                let map = entry.value_mut();
                map.entry(ConstraintGuid::nil())
                    .or_default()
                    .insert(name_id);
                for cg in constraint_guids {
                    map.entry(cg).or_default().insert(name_id);
                }
            };

        let exe_paths = &self.exe_paths;
        let cursor = std::sync::atomic::AtomicUsize::new(0);
        let op_ref = &op;

        let process = |exe_path: &PathBuf| {
            let pdb_path_for_exe = exe_path.with_extension("pdb");

            let result = (|| -> Result<()> {
                let mut analyzer = PdbAnalyzer::new(exe_path, &pdb_path_for_exe)?;
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
                        let name_id = intern(f.name);
                        merge_func(
                            f.guid,
                            name_id,
                            &mut f.constraints.into_iter().map(|c| c.guid),
                        );
                    },
                )?;
                Ok(())
            })();

            if let Err(e) = result {
                eprintln!("Error processing {}: {}", exe_path.display(), e);
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

        let strings = interner.into_inner().unwrap().strings;
        let constraint_map: BTreeMap<FunctionGuid, HashMap<ConstraintGuid, HashSet<u64>>> =
            constraint_to_names.into_iter().collect();

        let unique_constraints: usize = constraint_map
            .values()
            .map(|c| c.values().filter(|n| n.len() == 1).count())
            .sum();

        {
            let file = fs::File::create(output_path.as_ref())?;
            let mut writer = BufWriter::new(file);
            let db_writer = DbWriter::new(&constraint_map, &strings);
            db_writer.write(&mut writer)?;
        }

        Ok(DatabaseStats {
            total_functions: constraint_map.len(),
            unique_constraints,
            processed_files: self.exe_paths.len(),
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
