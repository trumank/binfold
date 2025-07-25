use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tracing::{debug, info};
use uuid::Uuid;

mod pe_loader;
use pe_loader::PeLoader;

use crate::constraint_matcher::FunctionCandidate;
use crate::warp::{compute_function_guid_with_contraints, compute_warp_uuid};
mod constraint_matcher;
mod mmap_source;
mod pdb_analyzer;
mod pdb_writer;
mod warp;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MatchInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    unique_name: Option<String>,
    total_matches: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    unique_count: Option<i64>,
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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
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
    // let pe = PeLoader::load(file)?;
    // let func = compute_function_guid_with_contraints(&pe, address)?;

    // info!(target: "warp_testing::pe", address = %format!("0x{address:x}"), guid = %func.guid, "Computed function GUID");

    // println!("Function at 0x{address:x}:");
    // println!("WARP UUID: {}", func.guid);
    // println!("Constraints:");
    // for constraint in &func.constraints {
    //     println!("  {constraint:x?}");
    // }

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
    use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
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
    use std::time::{SystemTime, UNIX_EPOCH};

    // some inspection queries
    // SELECT function_guids.id, printf('0x%x', address), guid, COUNT(*) AS constraint_count, (SELECT COUNT(*) FROM function_guids a WHERE a.guid = function_guids.guid) AS name_count, (SELECT value FROM strings WHERE id = function_name_id) FROM function_guids LEFT JOIN constraints ON constraints.function_guid_id = function_guids.id GROUP BY function_guid_id HAVING constraint_count > 5 AND name_count > 5 order BY COUNT(*) DESC;
    // SELECT guid, (SELECT value FROM strings WHERE id = function_name_id), group_concat(constraints.constraint_guid) from function_guids join constraints on constraints.function_guid_id = function_guids.id where guid = 'd3bc46e6-2d2f-508b-9da1-87925e0211b8' group by function_name_id;

    // Open database connection
    let conn = Connection::open(&database)?;

    // Set pragmas for better performance
    conn.execute_batch(
        "PRAGMA synchronous = OFF;
         PRAGMA journal_mode = MEMORY;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = 1000000;
         PRAGMA temp_store = MEMORY;
         PRAGMA mmap_size = 30000000000;",
    )?;

    // Create string table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS strings (
            id INTEGER PRIMARY KEY,
            value TEXT UNIQUE NOT NULL
        )",
        [],
    )?;

    // Create table if it doesn't exist (with integer references to strings)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS functions (
            id_function INTEGER PRIMARY KEY,
            address INTEGER NOT NULL,
            guid_function TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            id_exe_name INTEGER NOT NULL,
            id_function_name INTEGER NOT NULL,
            FOREIGN KEY (id_exe_name) REFERENCES strings(id),
            FOREIGN KEY (id_function_name) REFERENCES strings(id)
        )",
        [],
    )?;

    // Create constraints table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS constraints (
            id_constraint INTEGER PRIMARY KEY,
            id_function INTEGER NOT NULL,
            guid_constraint TEXT NOT NULL,
            offset INTEGER,
            FOREIGN KEY (id_function) REFERENCES functions(id_function) ON DELETE CASCADE
        )",
        [],
    )?;

    // Create indices for fast lookups
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_functions_guid ON functions(guid_function)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_functions_guid_fname ON functions(guid_function, id_function_name)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_functions_addr_exe ON functions(address, id_exe_name)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_strings_value ON strings(value)",
        [],
    )?;

    // Create indices for constraints table
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_constraints_id_function ON constraints(id_function)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_constraints_guid ON constraints(guid_constraint)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_constraints_guid_offset ON constraints(guid_constraint, offset)",
        [],
    )?;

    // Create string cache for fast lookups
    let string_cache: HashMap<String, i64> = HashMap::new();

    // Wrap connection and cache in Arc<Mutex> for thread-safe access
    let conn = Arc::new(Mutex::new(conn));
    let string_cache = Arc::new(Mutex::new(string_cache));

    // Create multi-progress for parallel progress bars
    let multi_progress = MultiProgress::new();

    let pb = ProgressBar::new(exe_paths.len() as u64).with_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, {eta}) Processing executables")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    multi_progress.add(pb.clone());

    let mut total_processed = 0;
    let mut total_failed = 0;

    // Get current unix timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Process executables sequentially to avoid OOM
    for exe_path in exe_paths {
        // Derive PDB path for this exe
        let pdb_path_for_exe = exe_path.with_extension("pdb");

        // Process this exe/pdb pair
        let result = (|| -> Result<()> {
            let mut analyzer = PdbAnalyzer::new(&exe_path, &pdb_path_for_exe)?;
            let function_guids =
                analyzer.compute_function_guids_with_progress(Some(multi_progress.clone()))?;

            // Get just the exe filename
            let exe_name = exe_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

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

                // Get exe_name_id once for this executable
                let exe_name_id = get_or_insert_string(&tx, &mut cache, exe_name)?;

                let mut stmt = tx.prepare(
                    "INSERT INTO functions (address, guid_function, id_exe_name, id_function_name, timestamp)
                     VALUES (?1, ?2, ?3, ?4, ?5)"
                )?;

                let mut constraint_stmt = tx.prepare(
                    "INSERT INTO constraints (id_function, guid_constraint, offset)
                     VALUES (?1, ?2, ?3)",
                )?;

                for func in &function_guids {
                    let function_name_id = get_or_insert_string(&tx, &mut cache, &func.name)?;

                    // Check if this function already exists
                    let existing_id: Option<i64> = tx
                        .query_row(
                            "SELECT id_function FROM functions WHERE address = ?1 AND id_exe_name = ?2",
                            params![func.address as i64, exe_name_id],
                            |row| row.get(0),
                        )
                        .ok();

                    let function_guid_id = if let Some(id) = existing_id {
                        // Update existing record
                        tx.execute(
                            "UPDATE functions SET guid_function = ?1, id_function_name = ?2, timestamp = ?3 WHERE id_function = ?4",
                            params![func.guid.to_string(), function_name_id, timestamp, id],
                        )?;

                        // Delete old constraints
                        tx.execute(
                            "DELETE FROM constraints WHERE id_function = ?1",
                            params![id],
                        )?;

                        id
                    } else {
                        // Insert new record
                        stmt.execute(params![
                            func.address as i64,
                            func.guid.to_string(),
                            exe_name_id,
                            function_name_id,
                            timestamp
                        ])?;
                        tx.last_insert_rowid()
                    };

                    // Insert constraints
                    for constraint in &func.constraints {
                        constraint_stmt.execute(params![
                            function_guid_id,
                            constraint.guid.to_string(),
                            constraint.offset
                        ])?;
                    }
                }
            }
            tx.commit()?;
            Ok(())
        })();

        pb.inc(1);

        match result {
            Ok(_) => total_processed += 1,
            Err(e) => {
                eprintln!("Error processing {}: {}", exe_path.display(), e);
                total_failed += 1;
            }
        }
    }

    pb.finish();
    multi_progress.clear().unwrap();

    println!("\nSummary:");
    println!("========");
    println!("Executables processed: {total_processed} succeeded, {total_failed} failed");
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

    // Open database connection if provided
    let db_conn = if let Some(db_path) = &database {
        use rusqlite::Connection;
        Some(Connection::open(db_path)?)
    } else {
        None
    };

    let mut results: Vec<FunctionResult> = Vec::new();

    // Create constraint matcher if database is provided
    let constraint_matcher = constraint_matcher::ConstraintMatcher::with_naive_solver();

    // Cache for GUID lookups to avoid repeated queries
    let mut cache_guid_lookups = HashMap::new();
    let mut cache_full_lookups = HashMap::new();

    // Process each function
    for (idx, func) in functions.iter().enumerate() {
        // Compute function GUID and constraints
        let func_guid = compute_function_guid_with_contraints(&pe, func.start)?;
        let guid = func_guid.guid;
        let size = pe.find_function_size(func.start)?;

        // Look up matches in database if available
        let (text_match_info, struct_match_info) = if let Some(ref conn) = db_conn {
            // Check cache first
            // Convert constraints to HashSet
            let query_constraints: HashSet<String> = func_guid
                .constraints
                .iter()
                .map(|c| c.guid.to_string())
                .collect();

            // Use helper function to determine match info
            use rusqlite::params;

            if let std::collections::hash_map::Entry::Vacant(e) = cache_guid_lookups.entry(guid) {
                // Query to get match statistics
                let mut stmt = conn.prepare(
                    "SELECT
                        COUNT(*) as total_count,
                        COUNT(DISTINCT id_function_name) as unique_count,
                        CASE
                            WHEN COUNT(DISTINCT id_function_name) = 1
                            THEN (SELECT value FROM strings WHERE id = id_function_name LIMIT 1)
                            ELSE NULL
                        END as unique_function_name
                    FROM functions
                    WHERE guid_function = ?1",
                )?;

                let row_result = stmt.query_row(params![guid.to_string()], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,            // total_count
                        row.get::<_, i64>(1)?,            // unique_count
                        row.get::<_, Option<String>>(2)?, // unique_function_name
                    ))
                });
                e.insert(row_result);
            }
            let row_result = cache_guid_lookups.get(&guid).unwrap();

            match row_result {
                Ok((total_count, _, Some(func_name))) => {
                    // Unique match by GUID alone
                    let text = format!(" [Unique match: {func_name}]");
                    let match_info = MatchInfo {
                        unique_name: Some(func_name.clone()),
                        total_matches: *total_count,
                        unique_count: None,
                    };
                    (text, Some(match_info))
                }
                Ok((total_count, unique_count, None)) if *unique_count > 1 => {
                    // Multiple unique names for this GUID - try constraint matching
                    // Load all candidates with this GUID
                    let candidates_entry = match cache_full_lookups.entry(guid) {
                        std::collections::hash_map::Entry::Occupied(entry) => {
                            tracing::debug!("Candidates for {guid} found in cache");
                            entry
                        }
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            tracing::debug!("Candidates for {guid} loading...");
                            let entry = entry.insert_entry(load_candidates_by_guid(conn, &guid)?);
                            tracing::debug!("Found {} candidates for {guid}", entry.get().len());
                            entry
                        }
                    };
                    let candidates = candidates_entry.get();

                    // Try to narrow down using constraints
                    tracing::debug!("Matching constraints");
                    if let Some(result) =
                        constraint_matcher.match_function(&query_constraints, candidates)
                    {
                        // Lookup function name in string table
                        let name = conn.query_row(
                            "SELECT value FROM strings WHERE id = ?1",
                            params![result.candidate.name_id],
                            |row| row.get::<_, String>(0),
                        )?;
                        let text = format!(" [Constraint match: {}]", name);
                        let match_info = MatchInfo {
                            unique_name: Some(name.clone()),
                            total_matches: 1,
                            unique_count: None,
                        };
                        (text, Some(match_info))
                    } else {
                        // No clear winner even with constraints
                        let text =
                            format!(" [{total_count} matches across {unique_count} unique names]");
                        let match_info = MatchInfo {
                            unique_name: None,
                            total_matches: *total_count,
                            unique_count: Some(*unique_count),
                        };
                        (text, Some(match_info))
                    }
                }
                _ => (String::new(), None),
            }
        } else {
            (String::new(), None)
        };

        // if format == OutputFormat::Text
        //     && struct_match_info
        //         .as_ref()
        //         .is_some_and(|i| i.unique_name.is_some())
        // {
        println!(
            "Function {} at 0x{:x}: GUID {}{}",
            idx + 1,
            func.start,
            guid,
            text_match_info
        );
        // }

        let result = FunctionResult {
            address: format!("0x{:x}", func.start),
            size,
            guid: guid.to_string(),
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

        for result in &results {
            let address = parse_hex(&result.address).unwrap_or(0);
            let size = result.size as u32;

            if let Some(name) = result
                .match_info
                .as_ref()
                .and_then(|mi| mi.unique_name.clone())
            {
                pdb_functions.push(pdb_writer::FunctionInfo {
                    address,
                    size,
                    name,
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
/// Load candidates from database for a given function GUID
pub fn load_candidates_by_guid(conn: &Connection, guid: &Uuid) -> Result<Vec<FunctionCandidate>> {
    // Use a single query with LEFT JOIN to get both functions and constraints
    // This avoids the issue with too many placeholders in the IN clause
    let mut stmt = conn.prepare(
        "SELECT 
            f.id_function,
            f.address,
            f.id_function_name,
            c.guid_constraint
        FROM functions f
        LEFT JOIN constraints c ON c.id_function = f.id_function
        WHERE f.guid_function = ?1
        ORDER BY f.id_function",
    )?;

    let mut candidates_map: HashMap<i64, (u64, i64, HashSet<String>)> = HashMap::new();

    let rows = stmt.query_map(params![guid.to_string()], |row| {
        Ok((
            row.get::<_, i64>(0)?,            // id_function
            row.get::<_, i64>(1)? as u64,     // address
            row.get::<_, i64>(2)?,            // id_function_name
            row.get::<_, Option<String>>(3)?, // guid_constraint (can be NULL)
        ))
    })?;

    for row in rows {
        let (func_id, address, name_id, constraint_guid) = row?;

        let entry = candidates_map
            .entry(func_id)
            .or_insert_with(|| (address, name_id, HashSet::new()));

        // Add constraint if it exists (LEFT JOIN can produce NULL)
        if let Some(constraint) = constraint_guid {
            entry.2.insert(constraint);
        }
    }

    // Convert the map to a vector of candidates
    let mut candidates = Vec::new();
    for (func_id, (address, name_id, constraints)) in candidates_map {
        candidates.push(FunctionCandidate {
            id: func_id,
            address,
            name_id,
            guid: guid.to_string(),
            constraints,
        });
    }

    Ok(candidates)
}
