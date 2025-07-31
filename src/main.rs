use anyhow::Result;
use clap::{Parser, Subcommand};
use indicatif::{ParallelProgressIterator as _, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use crate::db::{Db, DbWriter};
use crate::pe_loader::PeLoader;
use crate::warp::{ConstraintGuid, FunctionGuid, compute_function_guid_with_contraints};

mod db;
mod mmap_source;
mod pdb_analyzer;
mod pdb_writer;
mod pe_loader;
mod warp;

#[derive(Debug, Clone)]
struct MatchInfo {
    unique_name: String,
}

#[derive(Debug)]
struct FunctionResult {
    address: String,
    size: usize,
    guid: String,
    match_info: Option<MatchInfo>,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenDb(CommandGenDb),
    Analyze(CommandAnalyze),
    DumpDb(CommandDumpDb),
}

/// Create a database of function GUIDs/constraint GUIDs and their mappings to symbol names
#[derive(Parser)]
struct CommandGenDb {
    /// Paths to exe files or directories (can specify multiple)
    #[arg(short = 'e', long = "exe", required = true, num_args = 1..)]
    exe: Vec<PathBuf>,

    /// Output path for database
    #[arg(short = 'd', long = "database", required = true)]
    database: PathBuf,
}

/// Analyze an exe and optionally create a PDB
#[derive(Parser)]
struct CommandAnalyze {
    /// Path to exe file
    #[arg(short, long)]
    exe: PathBuf,

    /// Optional database path(s) for GUID lookups and symbol names
    #[arg(long)]
    database: Vec<PathBuf>,

    /// Generate PDB file with matched function names
    #[arg(long)]
    generate_pdb: bool,
}

/// Dump function and constraint information from a database as JSON
#[derive(Parser)]
struct CommandDumpDb {
    /// Path to database file
    #[arg(short, long)]
    database: PathBuf,

    /// Output JSON file path (defaults to stdout if not specified)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Only dump a specific function by its GUID
    #[arg(short, long)]
    function: Option<Uuid>,
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
        Commands::GenDb(cmd) => command_gen_db(cmd),
        Commands::Analyze(cmd) => command_analyze(cmd),
        Commands::DumpDb(cmd) => command_dump_db(cmd),
    }
}

fn command_gen_db(
    CommandGenDb {
        exe: exe_paths,
        database,
    }: CommandGenDb,
) -> Result<()> {
    use indicatif::{MultiProgress, ProgressBar};
    use pdb_analyzer::PdbAnalyzer;
    use std::fs;
    use std::io::BufWriter;

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

    use std::sync::{Arc, Mutex};

    // Create string cache for fast lookups
    let strings: Vec<String> = Vec::new();
    let string_to_index: HashMap<String, u64> = HashMap::new();

    // Wrap in Arc<Mutex> for thread-safe access
    let strings = Arc::new(Mutex::new(strings));
    let string_to_index = Arc::new(Mutex::new(string_to_index));

    // Create multi-progress for parallel progress bars
    let multi_progress = MultiProgress::new();

    let pb = ProgressBar::new(exe_paths.len() as u64)
        .with_style(progress_style())
        .with_message("Processing executables");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    multi_progress.add(pb.clone());

    // Shared data structure for building unique constraints
    let constraint_to_names: Arc<
        Mutex<BTreeMap<FunctionGuid, HashMap<ConstraintGuid, HashSet<u64>>>>,
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

            // Helper function to get or insert string
            let get_or_insert_string = |strings: &mut Vec<String>,
                                        string_to_index: &mut HashMap<String, u64>,
                                        value: &str|
             -> u64 {
                if let Some(&idx) = string_to_index.get(value) {
                    return idx;
                }

                let idx = strings.len() as u64;
                strings.push(value.to_string());
                string_to_index.insert(value.to_string(), idx);
                idx
            };

            {
                let mut strings = strings.lock().unwrap();
                let mut string_to_index = string_to_index.lock().unwrap();

                function_guids.iter().for_each(|func| {
                    let function_name_id =
                        get_or_insert_string(&mut strings, &mut string_to_index, &func.name);

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
                });
            }
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

    // Process executables using multiple threads
    std::thread::scope(|scope| -> Result<()> {
        let num_threads = 8;
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

    // Build the binary database structure
    let strings = Arc::try_unwrap(strings).unwrap().into_inner().unwrap();

    println!("Writing binary database...");

    {
        let file = fs::File::create(&database)?;
        let mut writer = BufWriter::new(file);
        let db_writer = DbWriter::new(&constraint_map, &strings);
        db_writer.write(&mut writer)?;
    }
    println!("Successfully wrote {unique_constraints} unique constraints to binary database");

    println!("\nSummary:");
    println!("========");
    println!("Database: {}", database.display());

    Ok(())
}

fn command_analyze(
    CommandAnalyze {
        exe: file,
        database,
        generate_pdb,
    }: CommandAnalyze,
) -> Result<()> {
    let pe = PeLoader::load(&file)?;
    let functions = pe.find_all_functions_from_exception_directory()?;

    println!("Found {} functions in exception directory", functions.len());

    let mmap = database
        .iter()
        .map(|path| {
            let file = std::fs::File::open(path)?;
            Ok(unsafe { memmap2::MmapOptions::new().map(&file)? })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut results: Vec<FunctionResult> = Vec::new();

    struct DbContext<'a> {
        cache_unique_constraints: HashMap<FunctionGuid, HashMap<ConstraintGuid, &'a str>>,
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
        let results = to_analyze
            .par_iter()
            .copied()
            .progress_with(pb)
            .map(|func| (func, compute_function_guid_with_contraints(&pe, func)))
            .collect::<Vec<(u64, Result<_>)>>();
        analyzed.extend(std::mem::take(&mut to_analyze));
        if recurse {
            to_analyze.extend(
                results
                    .iter()
                    .flat_map(|f| f.1.as_ref().ok())
                    .flat_map(|f| f.calls.iter().map(|c| c.target))
                    .filter(|t| !analyzed.contains(t)),
            );
        }
        for (addr, result) in results {
            match result {
                Ok(f) => {
                    function_guids.insert(f.guid);
                    analyzed_functions.push(f);
                }
                Err(err) => {
                    println!("Failed to analyze function at 0x{addr:x}: {:?}", err);
                }
            }
        }
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

    let db_context = if !mmap.is_empty() {
        let dbs = mmap
            .iter()
            .map(|m| Db::new(m))
            .collect::<Result<Vec<_>>>()?;

        let pb = new_pb(function_guids.len() as u64, "Loading function GUIDs");
        let cache_unique_constraints: HashMap<FunctionGuid, HashMap<ConstraintGuid, &str>> =
            function_guids
                .par_iter()
                .progress_with(pb)
                .map(|guid| -> Result<_> {
                    let mut constraints: HashMap<ConstraintGuid, HashSet<&str>> =
                        Default::default();
                    // collect unique symbols from each database
                    for db in &dbs {
                        for c in db.iter_constraints(guid) {
                            if c.symbol_count() == 1 {
                                constraints
                                    .entry(*c.guid())
                                    .or_default()
                                    .insert(c.symbols()?[0]);
                            }
                        }
                    }
                    // filter contraints that remain unique after merge
                    let constraints = constraints
                        .into_iter()
                        .filter_map(|(guid, symbols)| {
                            (symbols.len() == 1)
                                .then(|| (guid, symbols.into_iter().next().unwrap()))
                        })
                        .collect();
                    Ok((*guid, constraints))
                })
                .collect::<Result<_>>()?;

        println!("Found {} constraint guids", cache_unique_constraints.len());

        Some(DbContext {
            cache_unique_constraints,
        })
    } else {
        None
    };

    // Incrementally match functions
    let mut matched_functions: HashMap<u64, &str> = HashMap::new();
    let mut unmatched_functions: HashMap<u64, &warp::Function> =
        analyzed_functions.iter().map(|f| (f.address, f)).collect();

    // Keep matching until no more matches are found
    loop {
        let new_matches: Arc<Mutex<Vec<(u64, &str)>>> = Default::default();

        unmatched_functions.par_iter().try_for_each(
            |(_, func): (&u64, &&warp::Function)| -> Result<()> {
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

                    if let Some(func_name) = unique_match {
                        let mut lock = new_matches.lock().unwrap();
                        lock.push((func.address, func_name));
                    }
                }
                Ok(())
            },
        )?;

        let new_matches = new_matches.lock().unwrap();

        // If no new matches found, we're done
        if new_matches.is_empty() {
            break;
        }

        // Add new matches and remove from unmatched list
        let new_match_count = new_matches.len();
        for (addr, name) in &*new_matches {
            matched_functions.insert(*addr, name);
            unmatched_functions.remove(addr);
        }

        println!(
            "Found {} new matches in this iteration (total: {})",
            new_match_count,
            matched_functions.len()
        );
    }

    // Generate results for all functions
    for func in analyzed_functions.iter() {
        let size = pe.find_function_size(func.address)?;

        // Look up match info
        let (_text_match_info, struct_match_info) =
            if let Some(func_name) = matched_functions.get(&func.address) {
                let text = format!(" [Match: {func_name}]");
                let match_info = MatchInfo {
                    unique_name: func_name.to_string(),
                };
                (text, Some(match_info))
            } else {
                (String::new(), None)
            };

        // println!(
        //     "Function {} at 0x{:x}: GUID {}{}",
        //     idx + 1,
        //     func.address,
        //     func.guid,
        //     text_match_info
        // );

        let result = FunctionResult {
            address: format!("0x{:x}", func.address),
            size,
            guid: func.guid.to_string(),
            match_info: struct_match_info,
        };

        results.push(result);
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
        println!("Generating PDB file at: {}", pdb_path.display());

        pdb_writer::generate_pdb(&pe, &pdb_info, &pdb_functions, &pdb_path)?;

        println!(
            "PDB file generated successfully with {} functions",
            pdb_functions.len()
        );
    }
    Ok(())
}

fn command_dump_db(
    CommandDumpDb {
        database,
        output,
        function,
    }: CommandDumpDb,
) -> Result<()> {
    use std::fs;
    use std::io;
    use struson::writer::{JsonStreamWriter, JsonWriter};

    let file = fs::File::open(&database)?;
    let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };
    let db = Db::new(&mmap)?;

    let writer: Box<dyn io::Write> = if let Some(output_path) = output {
        Box::new(fs::File::create(output_path)?)
    } else {
        Box::new(io::stdout())
    };

    let mut json_writer = JsonStreamWriter::new(writer);
    json_writer.begin_array()?;

    let functions: Box<dyn Iterator<Item = FunctionGuid>> = if let Some(function) = function {
        Box::new(std::iter::once(FunctionGuid(function)))
    } else {
        Box::new(db.iter_functions())
    };

    // Stream functions one at a time
    for func_guid in functions {
        // Get constraints for this function
        let constraints = db.query_constraints_for_function(&func_guid)?;

        // Write function object
        json_writer.begin_object()?;
        json_writer.name("function")?;
        json_writer.string_value(&func_guid.to_string())?;

        json_writer.name("constraints")?;
        json_writer.begin_array()?;

        // Write constraints
        for (constraint_guid, symbols) in constraints {
            json_writer.begin_object()?;

            json_writer.name("constraint")?;
            json_writer.string_value(&constraint_guid.to_string())?;

            json_writer.name("symbols")?;
            json_writer.begin_array()?;

            // Write symbols
            for symbol in symbols {
                json_writer.string_value(symbol)?;
            }

            json_writer.end_array()?;
            json_writer.end_object()?;
        }

        json_writer.end_array()?;
        json_writer.end_object()?;
    }

    // Close JSON array and finish
    json_writer.end_array()?;
    json_writer.finish_document()?;

    Ok(())
}

fn progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, {eta}) {msg}")
        .unwrap()
        .progress_chars("#>-")
}
