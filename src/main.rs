use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

mod pe_loader;
use pe_loader::PeLoader;

use crate::warp::{
    compute_function_guid_with_contraints, compute_warp_uuid, compute_warp_uuid_from_pe,
};
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
enum DebugFlag {
    /// Debug function size analysis
    Size,
    /// Debug basic block identification
    Blocks,
    /// Debug instruction disassembly
    Instructions,
    /// Debug GUID calculation
    Guid,
    /// Enable all debug output
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Plain text output
    Text,
    /// JSON output
    Json,
}

#[derive(Debug, Clone, Default)]
pub struct DebugContext {
    pub debug_size: bool,
    pub debug_blocks: bool,
    pub debug_instructions: bool,
    pub debug_guid: bool,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Debug flags
    #[arg(short = 'D', long, value_enum)]
    debug: Vec<DebugFlag>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Pe(CommandPe),
    Example(CommandExample),
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

fn build_debug_context(flags: &[DebugFlag]) -> DebugContext {
    let mut ctx = DebugContext::default();
    for flag in flags {
        match flag {
            DebugFlag::Size => ctx.debug_size = true,
            DebugFlag::Blocks => ctx.debug_blocks = true,
            DebugFlag::Instructions => ctx.debug_instructions = true,
            DebugFlag::Guid => ctx.debug_guid = true,
            DebugFlag::All => {
                ctx.debug_size = true;
                ctx.debug_blocks = true;
                ctx.debug_instructions = true;
                ctx.debug_guid = true;
            }
        }
    }
    ctx
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let ctx = build_debug_context(&cli.debug);

    match cli.command {
        Commands::Pe(cmd) => command_pe(cmd, &ctx),
        Commands::Example(cmd) => command_example(cmd, &ctx),
        Commands::Pdb(cmd) => command_pdb(cmd, &ctx),
        Commands::Exception(cmd) => command_exception(cmd, &ctx),
    }
}

fn command_pe(CommandPe { file, address }: CommandPe, ctx: &DebugContext) -> Result<()> {
    let pe = PeLoader::load(file)?;
    let func = compute_function_guid_with_contraints(&pe, address, ctx)?;
    println!("Function at 0x{address:x}:");
    println!("WARP UUID: {}", func.guid);
    println!("contraints:");
    for constraint in func.constraints {
        println!("  {:x?}", constraint);
    }

    Ok(())
}

fn command_example(CommandExample: CommandExample, _ctx: &DebugContext) -> Result<()> {
    // Example x86_64 function bytes
    let function_bytes = vec![
        0x55, // push rbp
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0x48, 0x83, 0xec, 0x10, // sub rsp, 0x10
        0x89, 0x7d, 0xfc, // mov [rbp-4], edi
        0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
        0xe8, 0x1d, 0x00, 0x00, 0x00, // call 0x1030
        0x83, 0xc0, 0x01, // add eax, 1
        0xc9, // leave
        0xe9, 0x24, 0x00, 0x00, 0x00, // jmp 0x1040
    ];

    let mut calls = vec![];
    let warp_uuid = compute_warp_uuid(
        &function_bytes,
        0x1000,
        Some(&mut calls),
        &DebugContext::default(),
    );
    for call in calls {
        println!("{call:x?}");
    }
    println!("WARP UUID: {warp_uuid}");
    Ok(())
}

fn command_pdb(
    CommandPdb {
        exe_paths,
        database,
    }: CommandPdb,
    ctx: &DebugContext,
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
        "CREATE TABLE IF NOT EXISTS function_guids (
            address INTEGER NOT NULL,
            guid TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            exe_name_id INTEGER NOT NULL,
            function_name_id INTEGER NOT NULL,
            FOREIGN KEY (exe_name_id) REFERENCES strings(id),
            FOREIGN KEY (function_name_id) REFERENCES strings(id)
        )",
        [],
    )?;

    // Create indices for fast lookups
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_function_guids_guid ON function_guids(guid)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_function_guids_guid_fname ON function_guids(guid, function_name_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_strings_value ON strings(value)",
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
                analyzer.compute_function_guids_with_progress(ctx, Some(multi_progress.clone()))?;

            for func in &function_guids {
                println!("{func:#x?}");
            }

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
                    "INSERT OR REPLACE INTO function_guids (address, guid, exe_name_id, function_name_id, timestamp)
                     VALUES (?1, ?2, ?3, ?4, ?5)"
                )?;

                for func in &function_guids {
                    let function_name_id = get_or_insert_string(&tx, &mut cache, &func.name)?;

                    stmt.execute(params![
                        func.address as i64,
                        func.guid.to_string(),
                        exe_name_id,
                        function_name_id,
                        timestamp
                    ])?;
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
    ctx: &DebugContext,
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

    // Prepare statement for GUID lookups if database is provided
    let mut stmt = if let Some(ref conn) = db_conn {
        Some(conn.prepare(
            "SELECT
                COUNT(*) as total_count,
                COUNT(DISTINCT function_name_id) as unique_count,
                CASE
                    WHEN COUNT(DISTINCT function_name_id) = 1
                    THEN (SELECT value FROM strings WHERE id = function_name_id LIMIT 1)
                    ELSE NULL
                END as unique_function_name
            FROM function_guids
            WHERE guid = ?1",
        )?)
    } else {
        None
    };

    // Cache for GUID lookups to avoid repeated queries
    let mut guid_cache: std::collections::HashMap<String, (String, Option<MatchInfo>)> =
        std::collections::HashMap::new();

    let mut results: Vec<FunctionResult> = Vec::new();

    for (idx, func) in functions.iter().enumerate() {
        // let size = (func.end - func.start) as usize;

        let size = pe.find_function_size(func.start, ctx)?;
        let func_bytes = pe.read_at_va(func.start, size)?;
        let guid = compute_warp_uuid(func_bytes, func.start, None, ctx);

        // Look up GUID in database if available
        let (text_match_info, struct_match_info) = if stmt.is_some() {
            let guid_str = guid.to_string();

            // Check cache first
            if let Some(cached_info) = guid_cache.get(&guid_str).cloned() {
                cached_info
            } else {
                // Query database if not in cache
                let info = if let Some(ref mut stmt) = stmt {
                    use rusqlite::params;
                    let row_result = stmt.query_row(params![&guid_str], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,            // total_count
                            row.get::<_, i64>(1)?,            // unique_count
                            row.get::<_, Option<String>>(2)?, // unique_function_name
                        ))
                    });

                    match row_result {
                        Ok((total_count, _, Some(func_name))) => {
                            let text = format!(" [{total_count} matches: {func_name}]");
                            let match_info = MatchInfo {
                                unique_name: Some(func_name),
                                total_matches: total_count,
                                unique_count: None,
                            };
                            (text, Some(match_info))
                        }
                        Ok((total_count, unique_count, None)) => {
                            let text = format!(
                                " [{total_count} matches across {unique_count} unique names]"
                            );
                            let match_info = MatchInfo {
                                unique_name: None,
                                total_matches: total_count,
                                unique_count: Some(unique_count),
                            };
                            (text, Some(match_info))
                        }
                        Err(_) => (String::new(), None),
                    }
                } else {
                    (String::new(), None)
                };

                guid_cache.insert(guid_str, info.clone());
                info
            }
        } else {
            (String::new(), None)
        };

        if format == OutputFormat::Text
            && struct_match_info
                .as_ref()
                .is_some_and(|i| i.unique_name.is_some())
        {
            println!(
                "Function {} at 0x{:x}: GUID {}{}",
                idx + 1,
                func.start,
                guid,
                text_match_info
            );
        }

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
