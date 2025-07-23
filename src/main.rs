use anyhow::Result;
use clap::{Parser, Subcommand};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, Mnemonic, OpKind, Register,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::Range;
use std::path::PathBuf;
use uuid::{Uuid, uuid};

mod pe_loader;
use pe_loader::PeLoader;
mod mmap_source;
mod pdb_analyzer;
mod pdb_writer;

const FUNCTION_NAMESPACE: Uuid = uuid!("0192a179-61ac-7cef-88ed-012296e9492f");
const BASIC_BLOCK_NAMESPACE: Uuid = uuid!("0192a178-7a5f-7936-8653-3cbaa7d6afe7");

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
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute WARP UUID for a function in a PE file
    Pe {
        /// Path to the PE file
        #[arg(short, long)]
        file: PathBuf,

        /// Virtual address of the function
        #[arg(short, long, value_parser = parse_hex)]
        address: u64,

        /// Optional function size (will auto-detect if not provided)
        #[arg(short, long)]
        size: Option<usize>,
    },

    /// Debug analysis of a function
    Debug {
        /// Path to the PE file
        #[arg(short, long)]
        file: PathBuf,

        /// Virtual address of the function
        #[arg(short, long, value_parser = parse_hex)]
        address: u64,

        /// Debug flags (size, blocks, instructions, guid, all)
        #[arg(short = 'D', long)]
        debug: Vec<String>,

        /// Optional function size (will auto-detect if not provided)
        #[arg(short, long)]
        size: Option<usize>,
    },

    /// Run the example function
    Example,

    /// Analyze PDB file and compute GUIDs for all functions
    Pdb {
        /// Paths to PE/EXE files (can specify multiple)
        #[arg(short = 'e', long = "exe", required = true, num_args = 1..)]
        exe_paths: Vec<PathBuf>,

        /// Enable debug output
        #[arg(long)]
        debug: bool,

        /// SQLite database path
        #[arg(short = 'd', long = "database", required = true)]
        database: PathBuf,
    },

    /// Compute GUIDs for functions from PE exception directory
    Exception {
        /// Path to the PE file
        #[arg(short, long)]
        file: PathBuf,

        /// Output format (json, text)
        #[arg(short = 'o', long, default_value = "text")]
        format: String,

        /// Enable debug output
        #[arg(short, long)]
        debug: bool,

        /// Optional SQLite database path for GUID lookups
        #[arg(long = "database")]
        database: Option<PathBuf>,

        /// Generate PDB file with matched function names
        #[arg(long = "generate-pdb")]
        generate_pdb: bool,
    },
}

fn parse_hex(s: &str) -> Result<u64, std::num::ParseIntError> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse()
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pe {
            file,
            address,
            size,
        } => {
            let warp_uuid =
                compute_warp_uuid_from_pe(&file, address, size, &DebugContext::default())?;
            println!("Function at 0x{address:x}:");
            println!("WARP UUID: {warp_uuid}");
        }
        Commands::Debug {
            file,
            address,
            debug,
            size,
        } => {
            let mut ctx = DebugContext::default();
            for flag in debug {
                match flag.as_str() {
                    "size" => ctx.debug_size = true,
                    "blocks" => ctx.debug_blocks = true,
                    "instructions" => ctx.debug_instructions = true,
                    "guid" => ctx.debug_guid = true,
                    "all" => {
                        ctx.debug_size = true;
                        ctx.debug_blocks = true;
                        ctx.debug_instructions = true;
                        ctx.debug_guid = true;
                    }
                    _ => eprintln!("Unknown debug flag: {flag}"),
                }
            }

            println!("Debug analysis for function at 0x{address:x}");
            println!("Debug flags: {ctx:?}");
            println!("========================================\n");

            let warp_uuid = compute_warp_uuid_from_pe(&file, address, size, &ctx)?;
            println!("\nFinal WARP UUID: {warp_uuid}");
        }
        Commands::Example => {
            // Example x86_64 function bytes
            let function_bytes = vec![
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x48, 0x83, 0xec, 0x10, // sub rsp, 0x10
                0x89, 0x7d, 0xfc, // mov [rbp-4], edi
                0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
                0x83, 0xc0, 0x01, // add eax, 1
                0xc9, // leave
                0xc3, // ret
            ];

            let warp_uuid = compute_warp_uuid(&function_bytes, 0x1000, &DebugContext::default());
            println!("WARP UUID: {warp_uuid}");
        }
        Commands::Pdb {
            exe_paths,
            debug,
            database,
        } => {
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

            let debug_context = if debug {
                DebugContext {
                    debug_size: true,
                    debug_blocks: true,
                    debug_instructions: false,
                    debug_guid: true,
                }
            } else {
                DebugContext::default()
            };

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
                            .progress_chars("#>-"));
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
                    let function_guids = analyzer.compute_function_guids_with_progress(
                        &debug_context,
                        Some(multi_progress.clone()),
                    )?;

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
                                    tx.execute(
                                        "INSERT INTO strings (value) VALUES (?1)",
                                        params![value],
                                    )?;
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
                            let function_name_id =
                                get_or_insert_string(&tx, &mut cache, &func.name)?;

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
        }
        Commands::Exception {
            file,
            format,
            debug,
            database,
            generate_pdb,
        } => {
            let debug_context = if debug {
                DebugContext {
                    debug_size: false,
                    debug_blocks: false,
                    debug_instructions: false,
                    debug_guid: false,
                }
            } else {
                DebugContext::default()
            };

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

                let size = pe.find_function_size(func.start, &debug_context)?;
                let func_bytes = pe.read_at_va(func.start, size)?;
                let guid = compute_warp_uuid(func_bytes, func.start, &debug_context);

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

                if format == "text"
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

            if format == "json" {
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
        }
    }

    Ok(())
}

fn compute_warp_uuid_from_pe(
    path: &PathBuf,
    address: u64,
    size: Option<usize>,
    ctx: &DebugContext,
) -> Result<Uuid> {
    let pe = PeLoader::load(path)?;

    // Determine function size if not provided
    let func_size = match size {
        Some(s) => s,
        None => {
            if ctx.debug_size {
                println!("Auto-detecting function size...");
            }
            let detected_size = pe.find_function_size(address, ctx)?;
            if ctx.debug_size {
                println!("Detected function size: 0x{detected_size:x} bytes");
            }
            detected_size
        }
    };

    if !ctx.debug_size {
        println!("Function size: 0x{func_size:x} bytes");
    }

    // Read function bytes
    let func_bytes = pe.read_at_va(address, func_size)?;

    // Compute WARP UUID
    Ok(compute_warp_uuid(func_bytes, address, ctx))
}

pub fn compute_warp_uuid(raw_bytes: &[u8], base: u64, ctx: &DebugContext) -> Uuid {
    // Disassemble and identify basic blocks
    let basic_blocks = identify_basic_blocks(raw_bytes, base, ctx);

    if ctx.debug_blocks {
        println!("Identified {} basic blocks", basic_blocks.len());
    }

    // Create UUID for each basic block
    let mut block_uuids = Vec::new();
    for (&start_addr, &end_addr) in basic_blocks.iter() {
        // println!("{:x?}", (start_addr - base, end_addr - base, base));
        let block_bytes = &raw_bytes[(start_addr - base) as usize..(end_addr - base) as usize];
        let uuid = create_basic_block_guid(
            block_bytes,
            start_addr,
            base..(base + raw_bytes.len() as u64),
            ctx,
        );
        block_uuids.push((start_addr, uuid));

        if ctx.debug_guid {
            println!("Block 0x{start_addr:x}-0x{end_addr:x}: UUID {uuid}");
        }
    }

    // Print disassembly for each basic block if requested
    if ctx.debug_blocks {
        for (&start_addr, &end_addr) in &basic_blocks {
            println!("\nBasic block: 0x{start_addr:x} - 0x{end_addr:x}");
            println!("----------------------------------------");

            // Disassemble the block
            let block_start_offset = (start_addr - base) as usize;
            let block_end_offset = (end_addr - base) as usize;
            let block_bytes = &raw_bytes[block_start_offset..block_end_offset];

            let mut decoder = Decoder::with_ip(64, block_bytes, start_addr, DecoderOptions::NONE);
            let mut formatter = iced_x86::NasmFormatter::new();
            let mut output = String::new();

            while decoder.can_decode() {
                let instruction = decoder.decode();
                output.clear();
                formatter.format(&instruction, &mut output);
                println!("  0x{:x}: {}", instruction.ip(), output);
            }
        }
    }

    // Combine block UUIDs to create function UUID
    // Note: Despite WARP spec saying "highest to lowest", Binary Ninja
    // actually combines them in low-to-high address order
    let mut combined_bytes = Vec::new();
    for (_, uuid) in block_uuids.iter() {
        combined_bytes.extend_from_slice(uuid.as_bytes());
    }

    let function_uuid = Uuid::new_v5(&FUNCTION_NAMESPACE, &combined_bytes);

    if ctx.debug_guid {
        println!("\nFunction UUID calculation:");
        println!("  Block count: {}", block_uuids.len());
        println!("  Final UUID: {function_uuid}");
    }

    function_uuid
}

// Helper function to decode all instructions in a byte array
fn decode_instructions(raw_bytes: &[u8], base: u64) -> BTreeMap<u64, (Instruction, u64)> {
    let mut decoder = Decoder::with_ip(64, raw_bytes, base, DecoderOptions::NONE);
    let mut instructions = BTreeMap::new();

    while decoder.can_decode() {
        let start = decoder.ip();
        let instruction = decoder.decode();
        let end = decoder.ip();
        instructions.insert(start, (instruction, end));
    }

    instructions
}

struct Graph {
    incoming_edges: HashMap<u64, HashSet<u64>>,
    outgoing_edges: HashMap<u64, HashSet<u64>>,
    visited: HashSet<u64>,
}

// Helper function to build control flow graph
fn build_control_flow_graph(instructions: &BTreeMap<u64, (Instruction, u64)>, base: u64) -> Graph {
    let mut incoming_edges: HashMap<u64, HashSet<u64>> = HashMap::new();
    let mut outgoing_edges: HashMap<u64, HashSet<u64>> = HashMap::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(base);

    while let Some(addr) = queue.pop_front() {
        if visited.contains(&addr) {
            continue;
        }
        visited.insert(addr);

        if let Some((instruction, next_addr)) = instructions.get(&addr) {
            match instruction.flow_control() {
                FlowControl::Next | FlowControl::Call => {
                    // Regular instruction or call - edge to next
                    outgoing_edges.entry(addr).or_default().insert(*next_addr);
                    incoming_edges.entry(*next_addr).or_default().insert(addr);
                    queue.push_back(*next_addr);
                }
                FlowControl::UnconditionalBranch => {
                    // Unconditional jump - edge to target only
                    if let Some(target) = get_branch_target(instruction)
                        && instructions.contains_key(&target)
                    {
                        outgoing_edges.entry(addr).or_default().insert(target);
                        incoming_edges.entry(target).or_default().insert(addr);
                        queue.push_back(target);
                    }
                }
                FlowControl::ConditionalBranch => {
                    // Conditional jump - edges to both next and target
                    outgoing_edges.entry(addr).or_default().insert(*next_addr);
                    incoming_edges.entry(*next_addr).or_default().insert(addr);
                    queue.push_back(*next_addr);

                    if let Some(target) = get_branch_target(instruction)
                        && instructions.contains_key(&target)
                    {
                        outgoing_edges.entry(addr).or_default().insert(target);
                        incoming_edges.entry(target).or_default().insert(addr);
                        queue.push_back(target);
                    }
                }
                FlowControl::Return => {
                    // Return - no outgoing edges
                }
                _ => {}
            }
        }
    }

    Graph {
        incoming_edges,
        outgoing_edges,
        visited,
    }
}

// Helper function to identify block boundaries
fn identify_block_boundaries(
    instructions: &BTreeMap<u64, (Instruction, u64)>,
    incoming_edges: &HashMap<u64, HashSet<u64>>,
    outgoing_edges: &HashMap<u64, HashSet<u64>>,
    base: u64,
) -> BTreeSet<u64> {
    let mut block_starts = BTreeSet::new();
    block_starts.insert(base); // Entry point is always a block start

    // Linear sweep approach - more aggressive block identification
    let sorted_addrs: Vec<u64> = instructions.keys().copied().collect();

    for i in 0..sorted_addrs.len() {
        let addr = sorted_addrs[i];
        let (instruction, _) = &instructions[&addr];

        // Block start if multiple incoming edges
        if incoming_edges.get(&addr).map(|s| s.len()).unwrap_or(0) > 1 {
            block_starts.insert(addr);
        }

        // Block start if predecessor has multiple outgoing edges
        if let Some(predecessors) = incoming_edges.get(&addr) {
            for &pred in predecessors {
                if outgoing_edges.get(&pred).map(|s| s.len()).unwrap_or(0) > 1 {
                    block_starts.insert(addr);
                }
            }
        }

        // Mark targets of all branches as block starts
        match instruction.flow_control() {
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if let Some(target) = get_branch_target(instruction) {
                    block_starts.insert(target);
                }
                // Also mark the instruction after a branch as a block start
                if i + 1 < sorted_addrs.len() {
                    block_starts.insert(sorted_addrs[i + 1]);
                }
            }
            FlowControl::Return | FlowControl::IndirectBranch => {
                // Mark the next instruction as a block start (if it exists)
                if i + 1 < sorted_addrs.len() {
                    block_starts.insert(sorted_addrs[i + 1]);
                }
            }
            FlowControl::Call | FlowControl::IndirectCall => {
                // Don't mark after every call as a block start
                // Calls don't typically create new blocks unless there's
                // a branch to the return address
            }
            _ => {}
        }
    }

    block_starts
}

pub fn identify_basic_blocks(
    raw_bytes: &[u8],
    base: u64,
    ctx: &DebugContext,
) -> BTreeMap<u64, u64> {
    let instructions = decode_instructions(raw_bytes, base);

    if ctx.debug_blocks {
        println!(
            "Decoded {} instructions starting at 0x{:x}",
            instructions.len(),
            base
        );
    }

    // Build control flow graph edges and find reachable instructions
    let Graph {
        incoming_edges,
        outgoing_edges,
        visited,
    } = build_control_flow_graph(&instructions, base);

    if ctx.debug_blocks {
        println!(
            "Found {} reachable instructions via control flow",
            visited.len()
        );
    }

    // Identify basic block boundaries using both reachable and all instructions
    // This matches Binary Ninja's approach of finding all blocks in the function
    let block_starts =
        identify_block_boundaries(&instructions, &incoming_edges, &outgoing_edges, base);

    if ctx.debug_blocks {
        println!("Identified {} block start addresses", block_starts.len());
    }

    // Build basic blocks for ALL code (not just reachable)
    // This is key - Binary Ninja identifies blocks even in unreachable code
    let mut basic_blocks = BTreeMap::new();
    let starts: Vec<u64> = block_starts.iter().cloned().collect();

    for start in starts {
        // Include ALL blocks, not just reachable ones
        // Binary Ninja includes unreachable blocks in its analysis

        let mut end = start;

        // Find the end of this basic block
        let mut current = start;
        while let Some((instruction, next)) = instructions.get(&current) {
            // Include current instruction in block
            end = *next;

            // Stop if this instruction doesn't fall through to the next
            if matches!(
                instruction.flow_control(),
                FlowControl::UnconditionalBranch | FlowControl::Return
            ) {
                break;
            }

            // Stop if the next instruction is the start of another block
            if block_starts.contains(next) && *next != start {
                break;
            }

            // Move to next instruction
            current = *next;

            // Stop if we've reached the end of instructions
            if !instructions.contains_key(&current) {
                break;
            }
        }

        if start != end {
            basic_blocks.insert(start, end);
        }
    }

    basic_blocks
}

fn get_branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction.op_kind(0) {
        OpKind::NearBranch16 => Some(instruction.near_branch16() as u64),
        OpKind::NearBranch32 => Some(instruction.near_branch32() as u64),
        OpKind::NearBranch64 => Some(instruction.near_branch64()),
        _ => None,
    }
}

fn create_basic_block_guid(
    raw_bytes: &[u8],
    base: u64,
    function_bounds: Range<u64>,
    ctx: &DebugContext,
) -> Uuid {
    let instruction_bytes = get_instruction_bytes_for_guid(raw_bytes, base, function_bounds, ctx);
    Uuid::new_v5(&BASIC_BLOCK_NAMESPACE, &instruction_bytes)
}

fn get_instruction_bytes_for_guid(
    raw_bytes: &[u8],
    base: u64,
    function_bounds: Range<u64>,
    ctx: &DebugContext,
) -> Vec<u8> {
    use iced_x86::Formatter;

    let mut bytes = Vec::new();

    let mut decoder = Decoder::new(64, raw_bytes, DecoderOptions::NONE);
    decoder.set_ip(base);

    let mut formatter = iced_x86::NasmFormatter::new();
    let mut output = String::new();

    if ctx.debug_guid {
        println!("  Instruction processing for GUID:");
    }

    while decoder.can_decode() {
        let start = (decoder.ip() - base) as usize;
        let instruction = decoder.decode();
        let end = (decoder.ip() - base) as usize;
        let instr_bytes = &raw_bytes[start..end];

        output.clear();
        formatter.format(&instruction, &mut output);

        // NOPs handling is complex - Binary Ninja seems to include them
        // Only skip register-to-itself NOPs for hot-patching

        // Skip instructions that set a register to itself (if they're effectively NOPs)
        if is_register_to_itself_nop(&instruction) {
            if ctx.debug_guid {
                println!("    SKIP REG2REG: 0x{:x}: {}", instruction.ip(), output);
            }
            continue;
        }

        // Get instruction bytes, zeroing out relocatable instructions
        if is_relocatable_instruction(&instruction, function_bounds.clone()) {
            // Zero out relocatable instructions
            bytes.extend(vec![0u8; instr_bytes.len()]);
            if ctx.debug_guid {
                println!(
                    "    ZERO RELOC: 0x{:x}: {} | {:02x?}",
                    instruction.ip(),
                    output,
                    instr_bytes
                );
            }
        } else {
            // Use actual instruction bytes
            bytes.extend_from_slice(instr_bytes);
            if ctx.debug_guid {
                println!(
                    "    KEEP: 0x{:x}: {} | {:02x?}",
                    instruction.ip(),
                    output,
                    instr_bytes
                );
            }
        }
    }

    bytes
}

fn is_register_to_itself_nop(instruction: &Instruction) -> bool {
    if instruction.mnemonic() != Mnemonic::Mov {
        return false;
    }

    if instruction.op_count() != 2 {
        return false;
    }

    // Check if both operands are the same register
    if let (OpKind::Register, OpKind::Register) = (instruction.op_kind(0), instruction.op_kind(1)) {
        let reg0 = instruction.op_register(0);
        let reg1 = instruction.op_register(1);

        // For x86_64, mov edi, edi is NOT removed (implicit extension)
        // For x86, it would be removed
        if reg0 == reg1 && !has_implicit_extension(reg0) {
            return true;
        }
    }

    false
}

fn has_implicit_extension(reg: Register) -> bool {
    // In x86_64, 32-bit register operations zero-extend to 64 bits
    matches!(
        reg,
        Register::EAX
            | Register::EBX
            | Register::ECX
            | Register::EDX
            | Register::EDI
            | Register::ESI
            | Register::EBP
            | Register::ESP
            | Register::R8D
            | Register::R9D
            | Register::R10D
            | Register::R11D
            | Register::R12D
            | Register::R13D
            | Register::R14D
            | Register::R15D
    )
}

fn is_relocatable_instruction(instruction: &Instruction, function_bounds: Range<u64>) -> bool {
    // Check for direct calls - but only forward calls are relocatable
    if instruction.mnemonic() == Mnemonic::Call && instruction.op_count() > 0 {
        match instruction.op_kind(0) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                // All direct calls are relocatable
                return true;
            }
            _ => {}
        }
    }

    // Check for tail call jumps (unconditional jumps that likely go to other functions)
    if instruction.mnemonic() == Mnemonic::Jmp && instruction.op_count() > 0 {
        match instruction.op_kind(0) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                // Get the jump target
                let jump_target = match instruction.op_kind(0) {
                    OpKind::NearBranch16 => instruction.near_branch16() as u64,
                    OpKind::NearBranch32 => instruction.near_branch32() as u64,
                    OpKind::NearBranch64 => instruction.near_branch64(),
                    _ => 0,
                };

                // Check if jump target is outside function bounds
                if !function_bounds.contains(&jump_target) {
                    return true;
                }
            }
            _ => {}
        }
    }

    // Check for RIP-relative memory operands
    for i in 0..instruction.op_count() {
        if instruction.op_kind(i) == OpKind::Memory {
            // Check if it's RIP-relative (no base register, or RIP as base)
            if instruction.memory_base() == Register::RIP {
                return true;
            }

            // Also check for displacement-only addressing (no base, no index)
            // BUT exclude segment-relative addressing (GS, FS, etc)
            if instruction.memory_base() == Register::None
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() != 0
                && instruction.segment_prefix() == Register::None
            {
                return true;
            }
        }
    }

    false
}

fn print_disassembly_with_edges(raw_bytes: &[u8], base: u64) {
    // Decode all instructions
    let instructions = decode_instructions(raw_bytes, base);

    // Build control flow graph edges (we don't need visited for display)
    let Graph {
        incoming_edges,
        outgoing_edges,
        ..
    } = build_control_flow_graph(&instructions, base);

    // Identify block boundaries
    let block_starts =
        identify_block_boundaries(&instructions, &incoming_edges, &outgoing_edges, base);

    // Print disassembly with edge information - LINEAR SWEEP
    let mut formatter = iced_x86::NasmFormatter::new();
    let mut output = String::new();

    println!("Address      | In  | Out | Instruction");
    println!("-------------|-----|-----|-------------");

    // Do a fresh linear sweep to catch everything
    let mut decoder = Decoder::with_ip(64, raw_bytes, base, DecoderOptions::NONE);

    while decoder.can_decode() {
        let addr = decoder.ip();

        // Print block boundary if needed
        if block_starts.contains(&addr) && addr != base {
            println!("-------------|-----|-----|------------- BLOCK BOUNDARY");
        }

        let instruction = decoder.decode();

        let in_edges = incoming_edges.get(&addr).map(|s| s.len()).unwrap_or(0);
        let out_edges = outgoing_edges.get(&addr).map(|s| s.len()).unwrap_or(0);

        output.clear();
        formatter.format(&instruction, &mut output);

        println!("0x{addr:08x}  | {in_edges:3} | {out_edges:3} | {output}");
    }
}

// >>> with open('/tmp/functions.json', 'w') as f:
//     json.dump([{"guid": str(binaryninja.warp.get_function_guid(f)), "start": f.start, "blocks": [{"start": b.start, "end": b.end, "guid": str(binaryninja.warp.get_basic_block_guid(b))} for b in sorted(f.basic_blocks)]} for f in bv.functions if len(f.basic_blocks) == 150], f)

#[cfg(test)]
mod test {
    use super::*;

    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Exe {
        path: String,
        functions: Vec<Function>,
    }

    #[derive(Debug, Deserialize)]
    struct Function {
        guid: Uuid,
        start: u64,
        blocks: Vec<Block>,
    }

    #[derive(Debug, Deserialize)]
    struct Block {
        guid: Uuid,
        start: u64,
        end: u64,
    }

    #[test]
    fn test_json() {
        use std::io::Write;

        let f = std::io::BufReader::new(std::fs::File::open("functions.json").unwrap());
        let functions: Vec<Exe> = serde_json::from_reader(f).unwrap();

        let mut stats_file = std::fs::File::create("warp_test_stats.txt").unwrap();
        writeln!(stats_file, "WARP Function Analysis Statistics").unwrap();
        writeln!(stats_file, "==================================").unwrap();
        writeln!(
            stats_file,
            "Generated at: {:?}",
            std::time::SystemTime::now()
        )
        .unwrap();
        writeln!(stats_file).unwrap();

        let mut total_exact_matches = 0;
        let mut total_size_mismatches = 0;
        let mut total_blocks_analyzed = 0;
        let mut total_blocks_matched = 0;
        let mut total_functions = 0;

        // Collect detailed statistics
        let mut block_match_distribution: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut non_matching_functions = Vec::new();
        let mut perfect_block_no_guid = Vec::new();

        for exe in &functions {
            writeln!(stats_file, "\nExecutable: {}", exe.path).unwrap();
            writeln!(stats_file, "==========================================").unwrap();
            for (idx, function) in exe.functions.iter().enumerate() {
                writeln!(
                    stats_file,
                    "Function #{} at 0x{:x}",
                    idx + 1,
                    function.start
                )
                .unwrap();
                writeln!(stats_file, "  Expected GUID: {}", function.guid).unwrap();
                writeln!(stats_file, "  Expected blocks: {}", function.blocks.len()).unwrap();

                let Stats {
                    size_diff,
                    matching_blocks: blocks_matched,
                    found_blocks,
                    expected_blocks: blocks_total,
                    exact_match: guid_match,
                } = test_warp_function_from_binary(
                    &exe.path,
                    function.start,
                    function.guid,
                    function
                        .blocks
                        .iter()
                        .map(|b| (b.start, b.end, b.guid))
                        .collect(),
                );

                writeln!(stats_file, "  Size difference: {} bytes", size_diff).unwrap();
                writeln!(
                    stats_file,
                    "  Blocks matched (equal/found/expected): {blocks_matched}/{found_blocks}/{blocks_total} ({:.1}%)",
                    blocks_matched as f64 / blocks_total as f64 * 100.0
                )
                .unwrap();
                writeln!(
                    stats_file,
                    "  GUID match: {}",
                    if guid_match { "YES" } else { "NO" }
                )
                .unwrap();
                writeln!(stats_file).unwrap();

                if guid_match {
                    total_exact_matches += 1;
                }
                if size_diff != 0 {
                    total_size_mismatches += 1;
                }
                total_blocks_analyzed += blocks_total;
                total_blocks_matched += blocks_matched;
                total_functions += 1;

                let match_rate = blocks_matched as f64 / blocks_total as f64 * 100.0;
                let bucket = format!("{:.0}%", (match_rate / 10.0).floor() * 10.0);
                *block_match_distribution.entry(bucket).or_insert(0) += 1;

                if !guid_match {
                    non_matching_functions.push((
                        idx + 1,
                        function.start,
                        blocks_matched,
                        blocks_total,
                        match_rate,
                        exe.path.clone(),
                    ));
                    if blocks_matched == blocks_total && blocks_total == found_blocks {
                        perfect_block_no_guid.push((
                            idx + 1,
                            function.start,
                            function.guid.clone(),
                            exe.path.clone(),
                        ));
                    }
                }
            }
        }

        writeln!(stats_file, "Summary").unwrap();
        writeln!(stats_file, "=======").unwrap();
        writeln!(stats_file, "Total functions analyzed: {}", total_functions).unwrap();
        writeln!(
            stats_file,
            "Functions with exact GUID match: {}/{} ({:.1}%)",
            total_exact_matches,
            total_functions,
            total_exact_matches as f64 / total_functions as f64 * 100.0
        )
        .unwrap();
        writeln!(
            stats_file,
            "Functions with size mismatch: {}",
            total_size_mismatches
        )
        .unwrap();
        writeln!(
            stats_file,
            "Total basic blocks matched: {}/{} ({:.1}%)",
            total_blocks_matched,
            total_blocks_analyzed,
            total_blocks_matched as f64 / total_blocks_analyzed as f64 * 100.0
        )
        .unwrap();

        writeln!(stats_file, "\nBlock Match Distribution:").unwrap();
        writeln!(stats_file, "========================").unwrap();
        let mut buckets: Vec<_> = block_match_distribution.iter().collect();
        buckets.sort_by(|a, b| b.0.cmp(a.0));
        for (bucket, count) in buckets {
            writeln!(stats_file, "  {}: {} functions", bucket, count).unwrap();
        }

        writeln!(
            stats_file,
            "\nFunctions with 100% Block Match but Wrong GUID:"
        )
        .unwrap();
        writeln!(
            stats_file,
            "==============================================="
        )
        .unwrap();
        writeln!(stats_file, "Count: {}", perfect_block_no_guid.len()).unwrap();
        for (idx, addr, guid, exe_path) in perfect_block_no_guid.iter().take(10) {
            writeln!(
                stats_file,
                "  Function #{} at 0x{:x} (expected: {})",
                idx, addr, guid
            )
            .unwrap();
            writeln!(stats_file, "    in: {}", exe_path).unwrap();
        }
        if perfect_block_no_guid.len() > 10 {
            writeln!(
                stats_file,
                "  ... and {} more",
                perfect_block_no_guid.len() - 10
            )
            .unwrap();
        }

        writeln!(
            stats_file,
            "\nAll Non-Matching Functions by Block Match Rate:"
        )
        .unwrap();
        writeln!(stats_file, "==============================================").unwrap();
        non_matching_functions.sort_by(|a, b| b.4.partial_cmp(&a.4).unwrap());
        for (idx, addr, matched, total, rate, exe_path) in non_matching_functions.iter().take(20) {
            writeln!(
                stats_file,
                "  Function #{} at 0x{:x}: {}/{} blocks ({:.1}%)",
                idx, addr, matched, total, rate
            )
            .unwrap();
            writeln!(stats_file, "    in: {}", exe_path).unwrap();
        }
        if non_matching_functions.len() > 20 {
            writeln!(
                stats_file,
                "  ... and {} more",
                non_matching_functions.len() - 20
            )
            .unwrap();
        }
    }

    struct Stats {
        size_diff: i64,
        matching_blocks: usize,
        found_blocks: usize,
        expected_blocks: usize,
        exact_match: bool,
    }

    // Implementation of test WARP function from binary
    fn test_warp_function_from_binary(
        exe_path: impl AsRef<std::path::Path>,
        function_address: u64,
        expected_function_guid: Uuid,
        expected_blocks: Vec<(u64, u64, Uuid)>,
    ) -> Stats {
        // Load main.exe from root directory
        let pe = PeLoader::load(exe_path).expect("Failed to load main.exe");

        // Use the heuristic to find function size
        let function_size = pe
            .find_function_size(function_address, &DebugContext::default())
            .expect("Failed to determine function size");

        // Calculate expected size from the blocks
        let expected_size = if expected_blocks.is_empty() {
            0
        } else {
            let last_block = expected_blocks
                .iter()
                .max_by_key(|(_, end, _)| end)
                .unwrap();
            (last_block.1 - function_address) as usize
        };

        println!(
            "Function at 0x{:x}: detected size = 0x{:x}, expected size = 0x{:x} (diff = {})",
            function_address,
            function_size,
            expected_size,
            function_size as i64 - expected_size as i64
        );

        // Read the function bytes
        let function_bytes = pe
            .read_at_va(function_address, function_size)
            .expect("Failed to read function bytes");

        // Compute basic blocks
        let blocks =
            identify_basic_blocks(function_bytes, function_address, &DebugContext::default());

        println!("\nComparing basic blocks:");
        println!(
            "Start       | End         | Our GUID                             | Expected GUID                        | Match"
        );
        println!(
            "------------|-------------|--------------------------------------|--------------------------------------|-------"
        );

        let mut matching_blocks = 0;
        let mut mismatched_blocks = Vec::new();
        for &(start, end, expected_guid) in &expected_blocks {
            let our_end = blocks.get(&start);
            let our_guid = if let Some(&actual_end) = our_end {
                let block_bytes = &function_bytes
                    [(start - function_address) as usize..(actual_end - function_address) as usize];
                Some(create_basic_block_guid(
                    block_bytes,
                    start,
                    function_address..(function_address + function_size as u64),
                    &DebugContext::default(),
                ))
            } else {
                None
            };

            let guid_match = our_guid == Some(expected_guid);
            if guid_match {
                matching_blocks += 1;
            } else if our_end.is_some() {
                mismatched_blocks.push((start, end, *our_end.unwrap()));
            }

            println!(
                "0x{:08x} | 0x{:08x} | {} | {} | {}",
                start,
                end,
                our_guid
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "BLOCK_NOT_FOUND".to_string()),
                expected_guid,
                if guid_match { "YES" } else { "NO" }
            );
        }

        // Compute WARP UUID
        let warp_uuid =
            compute_warp_uuid(function_bytes, function_address, &DebugContext::default());
        println!("\nWARP UUID: {}", warp_uuid);
        println!("Expected:  {}", expected_function_guid);

        let exact_match = warp_uuid == expected_function_guid;
        let block_match_rate = matching_blocks as f64 / expected_blocks.len() as f64;

        println!("\nResults:");
        println!(
            "- Basic blocks: {}/{} match ({:.1}%)",
            matching_blocks,
            expected_blocks.len(),
            block_match_rate * 100.0
        );
        println!(
            "- WARP UUID: {}",
            if exact_match {
                "EXACT MATCH"
            } else {
                "MISMATCH"
            }
        );

        if !mismatched_blocks.is_empty() && exact_match {
            println!(
                "\nNote: Function UUID matches despite {} block mismatches:",
                mismatched_blocks.len()
            );
            for (start, expected_end, actual_end) in mismatched_blocks.iter().take(5) {
                println!(
                    "  Block 0x{:x}: expected end 0x{:x}, actual end 0x{:x} (diff: {})",
                    start,
                    expected_end,
                    actual_end,
                    *actual_end as i64 - *expected_end as i64
                );
            }
        }

        // Show a few basic blocks for debugging
        // if !exact_match || block_match_rate < 1.0 {
        //     println!("\nFirst 3 basic blocks:");
        //     let block_vec: Vec<_> = blocks.iter().take(3).collect();
        //     for &(&start_addr, &end_addr) in &block_vec {
        //         println!("\nBasic block: 0x{start_addr:x} - 0x{end_addr:x}");
        //         println!("----------------------------------------");

        //         let block_start_offset = (start_addr - function_address) as usize;
        //         let block_end_offset = (end_addr - function_address) as usize;

        //         if block_end_offset <= function_bytes.len() {
        //             let block_bytes = &function_bytes[block_start_offset..block_end_offset];

        //             let mut decoder =
        //                 Decoder::with_ip(64, block_bytes, start_addr, DecoderOptions::NONE);
        //             let mut formatter = iced_x86::NasmFormatter::new();
        //             let mut output = String::new();

        //             while decoder.can_decode() {
        //                 let instruction = decoder.decode();
        //                 output.clear();
        //                 formatter.format(&instruction, &mut output);
        //                 println!("  0x{:x}: {}", instruction.ip(), output);
        //             }
        //         }
        //     }
        // }

        // Assertions for test validation
        assert!(function_size > 0, "Function size should be greater than 0");
        assert!(blocks.len() > 0, "Should have at least one basic block");

        // Return statistics: (size_diff, blocks_matched, blocks_total, guid_match)
        let size_diff = function_size as i64 - expected_size as i64;
        Stats {
            size_diff,
            matching_blocks,
            found_blocks: blocks.len(),
            expected_blocks: expected_blocks.len(),
            exact_match,
        }
    }
}
