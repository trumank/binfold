use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ParallelProgressIterator as _, ProgressBar, ProgressIterator as _, ProgressStyle};
use rayon::prelude::*;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod pe_loader;
use pe_loader::PeLoader;

use crate::warp::{ConstraintGuid, FunctionGuid, compute_function_guid_with_contraints};
mod mmap_source;
mod pdb_analyzer;
mod pdb_writer;
mod warp;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MatchInfo {
    unique_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FunctionResult {
    address: String,
    size: usize,
    guid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_info: Option<MatchInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Plain text output
    Text,
    /// JSON output
    Json,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Pe(CommandPe),
    Pdb(CommandPdb),
    Exception(CommandException),
}

/// Compute WARP UUID for a function in a PE file
#[derive(Parser)]
struct CommandPe {
    /// Path to the PE file
    #[arg(short, long)]
    file: PathBuf,

    /// Virtual address of the function
    #[arg(short, long, value_parser = parse_hex)]
    address: u64,

    /// Optional SQLite database path for constraint lookups
    #[arg(short, long)]
    database: Option<PathBuf>,
}

/// Run the example function
#[derive(Parser)]
struct CommandExample;

/// Analyze PDB file and compute GUIDs for all functions
#[derive(Parser)]
struct CommandPdb {
    /// Paths to PE/EXE files (can specify multiple)
    #[arg(short = 'e', long = "exe", required = true, num_args = 1..)]
    exe_paths: Vec<PathBuf>,

    /// SQLite database path
    #[arg(short = 'd', long = "database", required = true)]
    database: PathBuf,
}

/// Compute GUIDs for functions from PE exception directory
#[derive(Parser)]
struct CommandException {
    /// Path to the PE file
    #[arg(short, long)]
    file: PathBuf,

    /// Output format
    #[arg(short = 'o', long, default_value_t = OutputFormat::Text, value_enum)]
    format: OutputFormat,

    /// Optional SQLite database path for GUID lookups
    #[arg(long = "database")]
    database: Option<PathBuf>,

    /// Generate PDB file with matched function names
    #[arg(long = "generate-pdb")]
    generate_pdb: bool,
}

fn parse_hex(s: &str) -> Result<u64, std::num::ParseIntError> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse()
    }
}

fn main() -> Result<()> {
    // Initialize tracing subscriber with environment filter
    // Users can control logging via RUST_LOG env var, e.g.:
    // RUST_LOG=warp_testing=debug
    // RUST_LOG=warp_testing::warp=trace,warp_testing::constraint_matcher=debug
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(
            fmt::layer()
                .with_span_events(fmt::format::FmtSpan::ENTER | fmt::format::FmtSpan::CLOSE)
                .with_timer(fmt::time::SystemTime)
                .with_level(true)
                .with_target(true),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Pe(cmd) => command_pe(cmd),
        Commands::Pdb(cmd) => command_pdb(cmd),
        Commands::Exception(cmd) => command_exception(cmd),
    }
}

fn command_pe(
    CommandPe {
        file,
        address,
        database,
    }: CommandPe,
) -> Result<()> {
    let pe = PeLoader::load(file)?;
    let func = compute_function_guid_with_contraints(&pe, address)?;

    info!(target: "warp_testing::pe", address = %format!("0x{address:x}"), guid = %func.guid, "Computed function GUID");

    println!("Function at 0x{address:x}:");
    println!("WARP UUID: {}", func.guid);
    println!("Constraints:");
    for constraint in &func.constraints {
        println!("  {constraint:x?}");
    }
    if !func.data_refs.is_empty() {
        println!("Data References:");
        for data_ref in &func.data_refs {
            let size_str = data_ref
                .estimated_size
                .map(|s| format!("{s} bytes"))
                .unwrap_or_else(|| "unknown".to_string());

            print!(
                "  target: 0x{:x}, offset: 0x{:x}, readonly: {}, estimated_size: {}",
                data_ref.target, data_ref.offset, data_ref.is_readonly, size_str
            );

            // For read-only data with no size (potential strings), try to show the content
            if data_ref.is_readonly && data_ref.estimated_size.is_none() {
                if let Some(data) = warp::read_string_data(&pe, data_ref.target) {
                    println!(" -> \"{}\"", String::from_utf8_lossy(&data));
                } else {
                    println!();
                }
            } else {
                println!();
            }
        }
    }

    // // If database is provided, look up matches and compare constraints
    // if let Some(db_path) = database {
    //     use constraint_matcher::ConstraintMatcher;
    //     use rusqlite::Connection;
    //     use std::collections::HashSet;

    //     let conn = Connection::open(db_path)?;

    //     // Create constraint matcher with naive solver
    //     let matcher = ConstraintMatcher::with_naive_solver();

    //     // Convert our constraints to a HashSet of GUIDs
    //     let query_constraints: HashSet<String> = func
    //         .constraints
    //         .iter()
    //         .map(|c| c.guid.to_string())
    //         .collect();

    //     println!("\n=== Function Matching ===");

    //     // Find matches by GUID (required)
    //     let candidates_by_guid = load_candidates_by_guid(&conn, &func.guid)?;
    //     if !candidates_by_guid.is_empty() {
    //         println!(
    //             "\nFound {} functions with matching GUID",
    //             candidates_by_guid.len()
    //         );

    //         // If multiple matches, try constraint matching to narrow down
    //         if candidates_by_guid.len() > 1 {
    //             println!("\nMultiple GUID matches found. Using constraints to narrow down...");

    //             if let Some(match_result) =
    //                 matcher.match_function(&query_constraints, &candidates_by_guid)
    //             {
    //                 println!("\nBest match found:");
    //                 println!(
    //                     "  Function: {} (0x{:x} in {})",
    //                     match_result.candidate.name,
    //                     match_result.candidate.address,
    //                     match_result.candidate.exe_name
    //                 );
    //                 println!("  Confidence: {:.2}", match_result.confidence);
    //                 println!(
    //                     "  Matching constraints: {}/{}",
    //                     match_result.matching_constraints, match_result.total_constraints
    //                 );
    //             } else {
    //                 println!("\nNo clear best match found among GUID matches");
    //             }
    //         } else {
    //             // Single match - it's the unique match
    //             let candidate = &candidates_by_guid[0];
    //             println!("\nUnique match found:");
    //             println!(
    //                 "  Function: {} (0x{:x} in {})",
    //                 candidate.name, candidate.address, candidate.exe_name
    //             );
    //         }

    //         // Show detailed comparison for all GUID matches
    //         if candidates_by_guid.len() > 1 {
    //             println!("\nDetailed comparison of all GUID matches:");
    //             for candidate in &candidates_by_guid {
    //                 println!(
    //                     "\n  {} (0x{:x} in {})",
    //                     candidate.name, candidate.address, candidate.exe_name
    //                 );

    //                 let our_constraint_set: HashSet<_> =
    //                     query_constraints.iter().cloned().collect();
    //                 let db_constraint_set: HashSet<_> =
    //                     candidate.constraints.iter().cloned().collect();

    //                 let matching = our_constraint_set.intersection(&db_constraint_set).count();
    //                 let only_in_ours: Vec<_> =
    //                     our_constraint_set.difference(&db_constraint_set).collect();
    //                 let only_in_db: Vec<_> =
    //                     db_constraint_set.difference(&our_constraint_set).collect();

    //                 println!(
    //                     "    Constraints: {} in DB, {} in our function, {} matching",
    //                     db_constraint_set.len(),
    //                     our_constraint_set.len(),
    //                     matching
    //                 );

    //                 if !only_in_ours.is_empty() {
    //                     debug!(target: "warp_testing::pe", "Only in our function: {} constraints", only_in_ours.len());
    //                     println!(
    //                         "    Only in our function: {} constraints",
    //                         only_in_ours.len()
    //                     );
    //                     for guid in only_in_ours.iter().take(3) {
    //                         println!("      - {guid}");
    //                     }
    //                     if only_in_ours.len() > 3 {
    //                         println!("      ... and {} more", only_in_ours.len() - 3);
    //                     }
    //                 }

    //                 if !only_in_db.is_empty() {
    //                     debug!(target: "warp_testing::pe", "Only in DB: {} constraints", only_in_db.len());
    //                     println!("    Only in DB: {} constraints", only_in_db.len());
    //                     for guid in only_in_db.iter().take(3) {
    //                         println!("      - {guid}");
    //                     }
    //                     if only_in_db.len() > 3 {
    //                         println!("      ... and {} more", only_in_db.len() - 3);
    //                     }
    //                 }
    //             }
    //         }
    //     } else {
    //         println!("\nNo functions found with matching GUID");
    //     }
    // }

    Ok(())
}

fn command_pdb(
    CommandPdb {
        exe_paths,
        database,
    }: CommandPdb,
) -> Result<()> {
    use indicatif::{MultiProgress, ProgressBar};
    use pdb_analyzer::PdbAnalyzer;
    use std::fs;

    // Expand directories to find EXE files with PDB files
    let mut expanded_exe_paths = Vec::new();

    fn find_exe_files_recursive(
        dir: &std::path::Path,
        exe_files: &mut Vec<PathBuf>,
    ) -> std::io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Recursively search subdirectories
                let _ = find_exe_files_recursive(&path, exe_files);
            } else if let Some(ext) = path.extension()
                && ext.eq_ignore_ascii_case("exe")
            {
                // Check if corresponding PDB exists
                let pdb_path = path.with_extension("pdb");
                if pdb_path.exists() {
                    exe_files.push(path);
                }
            }
        }
        Ok(())
    }

    for path in exe_paths {
        if path.is_dir() {
            // Recursively find all EXE files in the directory tree
            let _ = find_exe_files_recursive(&path, &mut expanded_exe_paths);
        } else {
            // It's a file, add it directly
            expanded_exe_paths.push(path);
        }
    }

    if expanded_exe_paths.is_empty() {
        anyhow::bail!("No EXE files with corresponding PDB files found");
    }

    // Sort for consistent output
    expanded_exe_paths.sort();

    println!(
        "Found {} EXE files with PDB files",
        expanded_exe_paths.len()
    );
    let exe_paths = expanded_exe_paths;

    use rusqlite::{Connection, params};
    use std::sync::{Arc, Mutex};

    // Open database connection
    let conn = Connection::open(&database)?;

    // Set pragmas for better performance
    conn.execute_batch(
        "PRAGMA synchronous = OFF;
         PRAGMA journal_mode = MEMORY;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = 1000000;
         PRAGMA temp_store = MEMORY;
         PRAGMA mmap_size = 30000000000;
         PRAGMA foreign_keys = OFF;",
    )?;

    // Create string table if it doesn't exist
    conn.execute(
        "CREATE TABLE strings (
            id INTEGER PRIMARY KEY,
            value TEXT UNIQUE NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE unique_constraints (
            guid_function BLOB NOT NULL,
            guid_constraint BLOB NOT NULL,
            id_function_name INTEGER NOT NULL,
            PRIMARY KEY (guid_function, guid_constraint),
            FOREIGN KEY (id_function_name) REFERENCES strings(id)
        )",
        [],
    )?;

    // Create string cache for fast lookups
    let string_cache: HashMap<String, i64> = HashMap::new();

    // Wrap connection and cache in Arc<Mutex> for thread-safe access
    let conn = Arc::new(Mutex::new(conn));
    let string_cache = Arc::new(Mutex::new(string_cache));

    // Create multi-progress for parallel progress bars
    let multi_progress = MultiProgress::new();

    let pb = ProgressBar::new(exe_paths.len() as u64)
        .with_style(progress_style())
        .with_message("Processing executables");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    multi_progress.add(pb.clone());

    // Shared data structure for building unique constraints
    let constraint_to_names: Arc<
        Mutex<HashMap<FunctionGuid, HashMap<ConstraintGuid, HashSet<i64>>>>,
    > = Default::default();

    // Process executables sequentially to avoid OOM
    let constraint_to_names_clone = constraint_to_names.clone();
    let process = |exe_path: &PathBuf| -> Result<()> {
        // Derive PDB path for this exe
        let pdb_path_for_exe = exe_path.with_extension("pdb");

        // Process this exe/pdb pair
        let result = (|| -> Result<()> {
            let mut analyzer = PdbAnalyzer::new(exe_path, &pdb_path_for_exe)?;
            let function_guids =
                analyzer.compute_function_guids_with_progress(Some(multi_progress.clone()))?;

            // Insert all records in a single transaction
            let mut conn = conn.lock().unwrap();
            let mut cache = string_cache.lock().unwrap();
            let tx = conn.transaction()?;
            {
                // Helper function to get or insert string
                let get_or_insert_string = |tx: &rusqlite::Transaction,
                                            cache: &mut HashMap<String, i64>,
                                            value: &str|
                 -> Result<i64> {
                    if let Some(&id) = cache.get(value) {
                        return Ok(id);
                    }

                    // Try to find existing string
                    let id = match tx.query_row(
                        "SELECT id FROM strings WHERE value = ?1",
                        params![value],
                        |row| row.get(0),
                    ) {
                        Ok(id) => id,
                        Err(rusqlite::Error::QueryReturnedNoRows) => {
                            // Insert new string
                            tx.execute("INSERT INTO strings (value) VALUES (?1)", params![value])?;
                            tx.last_insert_rowid()
                        }
                        Err(e) => return Err(e.into()),
                    };

                    cache.insert(value.to_string(), id);
                    Ok(id)
                };

                function_guids.iter().try_for_each(|func| -> Result<()> {
                    let function_name_id = get_or_insert_string(&tx, &mut cache, &func.name)?;

                    // Insert constraints and build constraint_to_names mapping
                    let mut constraint_map = constraint_to_names_clone.lock().unwrap();
                    for constraint in [ConstraintGuid::nil()]
                        .into_iter()
                        .chain(func.constraints.iter().map(|c| c.guid))
                    {
                        // Update constraint_to_names for unique constraint calculation
                        constraint_map
                            .entry(func.guid)
                            .or_default()
                            .entry(constraint)
                            .or_default()
                            .insert(function_name_id);
                    }

                    Ok(())
                })?;
            }
            tx.commit()?;
            Ok(())
        })();

        pb.inc(1);

        match result {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error processing {}: {}", exe_path.display(), e);
            }
        }

        Ok(())
    };

    // don't use par_iter to iterate games because we only need a couple threads
    // will end up bound by sqlite insertion anyway
    std::thread::scope(|scope| -> Result<()> {
        let num_threads = 4;
        let tasks: Vec<_> = exe_paths
            .chunks(exe_paths.len().div_ceil(num_threads))
            .map(|chunk| {
                scope.spawn(move || -> Result<()> {
                    for path in chunk {
                        process(path)?;
                    }
                    Ok(())
                })
            })
            .collect();
        for task in tasks {
            task.join().unwrap()?;
        }
        Ok(())
    })?;

    pb.finish();
    multi_progress.clear().unwrap();

    // Process unique constraints
    println!("\nProcessing unique constraints...");
    let constraint_map = constraint_to_names.lock().unwrap();

    let unique_constraints: usize = constraint_map
        .values()
        .map(|c| c.values().filter(|n| n.len() == 1).count())
        .sum();

    println!("Found {unique_constraints} unique constraints");

    {
        let mut conn = conn.lock().unwrap();

        // Insert all unique constraints
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO unique_constraints (guid_function, guid_constraint, id_function_name) 
                 VALUES (?1, ?2, ?3)",
            )?;

            let iter = constraint_map.iter().flat_map(|(f, c)| {
                c.iter()
                    .flat_map(|(c, n)| (n.len() == 1).then(|| (*f, *c, n.iter().next().unwrap())))
            });
            let pb = ProgressBar::new(unique_constraints as u64).with_style(progress_style());
            for (guid_function, guid_constraint, id_function_name) in iter.progress_with(pb) {
                stmt.execute(params![guid_function, guid_constraint, id_function_name])?;
            }
        }
        tx.commit()?;

        println!("Creating indexes");

        conn.execute(
            "CREATE INDEX idx_unique_constraints_function_constraint_name ON unique_constraints(guid_function, guid_constraint, id_function_name)",
            [],
        )?;

        println!(
            "Successfully inserted {unique_constraints} unique constraints into the table"
        );
    }

    println!("\nSummary:");
    println!("========");
    println!("Database: {}", database.display());

    Ok(())
}

fn command_exception(
    CommandException {
        file,
        format,
        database,
        generate_pdb,
    }: CommandException,
) -> Result<()> {
    let pe = PeLoader::load(&file)?;
    let functions = pe.find_all_functions_from_exception_directory()?;

    println!("Found {} functions in exception directory", functions.len());

    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        | rusqlite::OpenFlags::SQLITE_OPEN_URI
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;

    let conn = if let Some(db_path) = &database {
        Some(Connection::open_with_flags(db_path, flags)?)
    } else {
        None
    };

    let mut results: Vec<FunctionResult> = Vec::new();

    struct DbContext {
        cache_unique_constraints: HashMap<FunctionGuid, HashMap<ConstraintGuid, i64>>,
    }

    let new_pb = |len, msg| {
        ProgressBar::new(len)
            .with_style(progress_style())
            .with_message(msg)
    };

    let recurse = true;

    let mut to_analyze: HashSet<u64> = functions.iter().map(|f| f.start).collect();
    let mut analyzed: HashSet<u64> = Default::default();
    type Res = (HashSet<FunctionGuid>, Vec<warp::Function>);
    let (mut function_guids, mut analyzed_functions): Res = Default::default();
    while !to_analyze.is_empty() {
        println!("Found {} functions to analyze", to_analyze.len());
        let pb = new_pb(to_analyze.len() as u64, "Analyzing functions");
        let (new_guids, new_functions): Res = to_analyze
            .par_iter()
            .copied()
            .progress_with(pb)
            .map(|func| compute_function_guid_with_contraints(&pe, func).map(|f| (f.guid, f)))
            .collect::<Result<Res>>()?;
        analyzed.extend(std::mem::take(&mut to_analyze));
        if recurse {
            to_analyze.extend(
                new_functions
                    .iter()
                    .flat_map(|f| f.calls.iter().map(|c| c.target))
                    .filter(|t| !analyzed.contains(t)),
            );
        }
        function_guids.extend(new_guids);
        analyzed_functions.extend(new_functions);
    }
    analyzed_functions.sort_by_key(|f| f.address);

    // Build parent call constraints and keep callers map for later use
    let mut callers: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
    let mut functions_by_addr: HashMap<u64, FunctionGuid> = HashMap::new();

    for func in &analyzed_functions {
        functions_by_addr.insert(func.address, func.guid);
        for call in &func.calls {
            callers
                .entry(call.target)
                .or_default()
                .push((func.address, call.offset));
        }
    }

    // Add parent constraints to functions
    for func in &mut analyzed_functions {
        if let Some(parent_calls) = callers.get(&func.address) {
            for (parent_addr, offset) in parent_calls {
                if let Some(parent_guid) = functions_by_addr.get(parent_addr) {
                    func.constraints.push(warp::Constraint {
                        guid: warp::ConstraintGuid::from_parent_call(*parent_guid),
                        offset: Some(*offset as i64),
                    });
                }
            }
        }
    }

    println!(
        "Found {} unique funcs and {} total funcs",
        function_guids.len(),
        analyzed_functions.len()
    );

    let db_context = if let Some(database) = &database {
        let pb = new_pb(function_guids.len() as u64, "Querying function GUIDs");
        let cache_unique_constraints: HashMap<FunctionGuid, HashMap<ConstraintGuid, i64>> =
            function_guids
                .par_iter()
                .progress_with(pb)
                .map_init(
                    || Connection::open_with_flags(database, flags).unwrap(),
                    |conn, guid| -> Result<_> {
                        let mut stmt = conn.prepare(
                            "SELECT guid_constraint, id_function_name
                            FROM unique_constraints
                            WHERE guid_function = ?1",
                        )?;
                        let res = stmt
                            .query_map(params![guid], |row| Ok((row.get(0)?, row.get(1)?)))?
                            .collect::<rusqlite::Result<HashMap<ConstraintGuid, i64>>>()?;
                        Ok((*guid, res))
                    },
                )
                .collect::<Result<_>>()?;

        println!("Found {} constraint guids", cache_unique_constraints.len());

        Some(DbContext {
            cache_unique_constraints,
        })
    } else {
        None
    };

    // Incrementally match functions
    let mut matched_functions: HashMap<u64, String> = HashMap::new();
    let mut unmatched_functions: Vec<&warp::Function> = analyzed_functions.iter().collect();

    // Keep matching until no more matches are found
    loop {
        let mut new_matches = Vec::new();

        for func in &unmatched_functions {
            // Add symbol-based constraints for already matched functions
            let mut enhanced_constraints = func.constraints.clone();

            // Check if any of our calls have been matched - add symbol constraints
            for call in &func.calls {
                if let Some(target_name) = matched_functions.get(&call.target) {
                    let target_symbol = warp::SymbolGuid::from_symbol(target_name);
                    enhanced_constraints.push(warp::Constraint {
                        guid: warp::ConstraintGuid::from_symbol_child_call(target_symbol),
                        offset: Some(call.offset as i64),
                    });
                }
            }

            // Check if any functions that call us have been matched - add symbol parent constraints
            if let Some(parent_calls) = callers.get(&func.address) {
                for (parent_addr, offset) in parent_calls {
                    if let Some(parent_name) = matched_functions.get(parent_addr) {
                        let parent_symbol = warp::SymbolGuid::from_symbol(parent_name);
                        enhanced_constraints.push(warp::Constraint {
                            guid: warp::ConstraintGuid::from_symbol_parent_call(parent_symbol),
                            offset: Some(*offset as i64),
                        });
                    }
                }
            }

            // Try to match with enhanced constraints
            if let Some(db_context) = &db_context {
                let constraints = db_context.cache_unique_constraints.get(&func.guid).unwrap();

                let unique_match = constraints.get(&ConstraintGuid::nil()).or_else(|| {
                    let query_constraints: HashSet<ConstraintGuid> =
                        enhanced_constraints.iter().map(|c| c.guid).collect();
                    query_constraints.iter().find_map(|c| constraints.get(c))
                });

                if let Some(name_id) = unique_match {
                    let func_name = conn.as_ref().unwrap().query_row(
                        "SELECT value FROM strings WHERE id = ?1",
                        params![name_id],
                        |row| row.get::<_, String>(0),
                    )?;
                    new_matches.push((func.address, func_name));
                }
            }
        }

        // If no new matches found, we're done
        if new_matches.is_empty() {
            break;
        }

        // Add new matches and remove from unmatched list
        let new_match_count = new_matches.len();
        for (addr, name) in new_matches {
            matched_functions.insert(addr, name);
            unmatched_functions.retain(|f| f.address != addr);
        }

        println!(
            "Found {} new matches in this iteration (total: {})",
            new_match_count,
            matched_functions.len()
        );
    }

    // Generate results for all functions
    for (idx, func) in analyzed_functions.iter().enumerate() {
        let size = pe.find_function_size(func.address)?;

        // Look up match info
        let (text_match_info, struct_match_info) =
            if let Some(func_name) = matched_functions.get(&func.address) {
                let text = format!(" [Match: {func_name}]");
                let match_info = MatchInfo {
                    unique_name: func_name.clone(),
                };
                (text, Some(match_info))
            } else {
                (String::new(), None)
            };

        println!(
            "Function {} at 0x{:x}: GUID {}{}",
            idx + 1,
            func.address,
            func.guid,
            text_match_info
        );

        let result = FunctionResult {
            address: format!("0x{:x}", func.address),
            size,
            guid: func.guid.to_string(),
            match_info: struct_match_info,
        };

        results.push(result);
    }

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    }

    // Generate PDB if requested
    if generate_pdb {
        let pdb_info = pdb_writer::extract_pdb_info(&pe)?;

        // Build function info list from results
        let mut pdb_functions = Vec::new();

        for result in results {
            let address = parse_hex(&result.address).unwrap_or(0);
            let size = result.size as u32;

            if let Some(info) = result.match_info {
                pdb_functions.push(pdb_writer::FunctionInfo {
                    address,
                    size,
                    name: info.unique_name,
                });
            }
        }

        // Generate PDB file
        let pdb_path = file.with_extension("pdb");
        println!("\nGenerating PDB file at: {}", pdb_path.display());

        pdb_writer::generate_pdb(&pe, &pdb_info, &pdb_functions, &pdb_path)?;

        println!(
            "PDB file generated successfully with {} functions",
            pdb_functions.len()
        );
    }
    Ok(())
}

fn progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, {eta}) {msg}")
        .unwrap()
        .progress_chars("#>-")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_query() -> Result<()> {
        use rusqlite::Connection;
        let conn = Connection::open("new_giga.db")?;

        // let mut stmt = conn.prepare(
        //     "
        // SELECT
        //     COUNT(DISTINCT f.id_function_name) as unique_count,
        //     MIN(f.id_function_name) as name_id
        // FROM functions f
        // WHERE f.guid_function = '7286f2ec-31c4-5743-8061-3e87c3310b6b'
        // AND EXISTS (
        //     SELECT 1 FROM constraints c
        //     WHERE c.id_function = f.id_function
        //     AND c.guid_constraint = '85438e2f-3853-57ab-9bdd-b1f9e256a220'
        // );
        // ",
        // )?;

        let mut stmt = conn.prepare(
            "SELECT
                COUNT(DISTINCT f.id_function_name) as unique_count,
                MIN(f.id_function_name) as name_id
            FROM functions f
            WHERE f.guid_function = ?1 
            AND EXISTS (
                SELECT 1 FROM constraints c 
                WHERE c.id_function = f.id_function 
                AND c.guid_constraint = ?2
            )",
        )?;

        // time.busy=5.36s
        // Looking up function 4910ea65-c576-55a3-b6df-b070c4c701f2
        //  with constraint 31f6cc3a-d351-51c8-96b2-3fc57391f8a6

        // let row_result = stmt.query_row(params![guid.to_string()], |row| {
        let row_result = stmt.query_row(
            params![
                "4910ea65-c576-55a3-b6df-b070c4c701f2",
                "31f6cc3a-d351-51c8-96b2-3fc57391f8a6"
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?, // total_count
                    row.get::<_, i64>(1)?, // unique_count
                ))
            },
        )?;

        dbg!(row_result);

        Ok(())
    }

    #[test]
    fn test_unique_constraint_query() -> Result<()> {
        use rusqlite::Connection;
        use std::collections::HashMap;

        let mut conn = Connection::open("erm.db")?;

        conn.execute_batch(
            "PRAGMA synchronous = OFF;
             PRAGMA journal_mode = MEMORY;
             PRAGMA temp_store = MEMORY;
             PRAGMA cache_size = 1000000;
             PRAGMA temp_store = MEMORY;
             PRAGMA mmap_size = 30000000000;
             PRAGMA foreign_keys = OFF;",
        )?;

        let unique_constraints = {
            // Step 1: Fetch all functions (id_function -> (guid_function, id_function_name))
            println!("fetching functions");
            let mut functions_stmt =
                conn.prepare("SELECT id_function, guid_function, id_function_name FROM functions")?;

            let mut function_info: HashMap<i64, (FunctionGuid, i64)> = HashMap::new();
            let function_rows = functions_stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, FunctionGuid>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;

            for row in function_rows {
                let (id_function, guid_function, id_function_name) = row?;
                function_info.insert(id_function, (guid_function, id_function_name));
            }

            println!("Loaded {} functions", function_info.len());

            // Step 2: Fetch all constraints
            println!("fetching constraints");
            let mut constraints_stmt =
                conn.prepare("SELECT id_function, guid_constraint FROM constraints")?;

            // Group by (function_guid, constraint_guid) and collect unique function names
            let mut constraint_to_names: HashMap<(FunctionGuid, ConstraintGuid), HashSet<i64>> =
                HashMap::new();

            let constraint_rows = constraints_stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, ConstraintGuid>(1)?))
            })?;

            let mut constraint_count = 0;
            let pb = ProgressBar::new(conn.query_row(
                "SELECT COUNT(guid_constraint) FROM constraints",
                [],
                |row| row.get(0),
            )?)
            .with_style(progress_style());
            for row in constraint_rows.progress_with(pb) {
                let (id_function, guid_constraint) = row?;
                constraint_count += 1;

                // Join: look up the function guid and name for this function id
                if let Some(&(guid_function, id_function_name)) = function_info.get(&id_function) {
                    constraint_to_names
                        .entry((guid_function, guid_constraint))
                        .or_default()
                        .insert(id_function_name);
                }
            }

            println!("Processed {} constraints", constraint_count);

            // Step 3: Filter to only (function_guid, constraint_guid) pairs that have exactly one unique function name
            let unique_constraints: Vec<(FunctionGuid, ConstraintGuid, i64)> = constraint_to_names
                .into_iter()
                .filter_map(|((guid_function, constraint_guid), name_ids)| {
                    if name_ids.len() == 1 {
                        Some((
                            guid_function,
                            constraint_guid,
                            *name_ids.iter().next().unwrap(),
                        ))
                    } else {
                        None
                    }
                })
                .collect();

            unique_constraints
        };

        println!("Found {} unique constraints", unique_constraints.len());
        for (guid_function, constraint_guid, function_name_id) in unique_constraints.iter().take(10)
        {
            println!(
                "Function: {:?}, Constraint: {:?}, Function Name ID: {}",
                guid_function, constraint_guid, function_name_id
            );
        }

        // Step 4: Create table and insert results
        println!("Creating unique_constraints table and inserting results...");

        // Create the table if it doesn't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS unique_constraints (
                guid_function BLOB NOT NULL,
                guid_constraint BLOB NOT NULL,
                id_function_name INTEGER NOT NULL,
                PRIMARY KEY (guid_function, guid_constraint),
                FOREIGN KEY (id_function_name) REFERENCES strings(id)
            )",
            [],
        )?;

        // Insert all unique constraints
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO unique_constraints (guid_function, guid_constraint, id_function_name) 
                 VALUES (?1, ?2, ?3)",
            )?;

            let pb = ProgressBar::new(unique_constraints.len() as u64).with_style(progress_style());
            for (guid_function, constraint_guid, function_name_id) in
                unique_constraints.iter().progress_with(pb)
            {
                stmt.execute(params![guid_function, constraint_guid, function_name_id])?;
            }
        }
        tx.commit()?;

        println!(
            "Successfully inserted {} unique constraints into the table",
            unique_constraints.len()
        );

        conn.execute(
            "CREATE INDEX idx_unique_constraints ON unique_constraints(guid_function, guid_constraint, id_function_name)",
            [],
        )?;

        Ok(())
    }
}
