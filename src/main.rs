use anyhow::Result;
use binfold::db::{Db, FunctionGuid};
use binfold::progress::IndicatifProgressBar;
use binfold::{BinfoldAnalyzer, DatabaseBuilder};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

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
    DbInfo(CommandDbInfo),
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

    /// Cap on binaries loaded into memory simultaneously.
    #[arg(long)]
    parallel: Option<usize>,
}

/// Analyze an exe and optionally create a PDB
#[derive(Parser)]
struct CommandAnalyze {
    /// Path to exe file
    #[arg(short, long)]
    exe: PathBuf,

    /// Optional database path for GUID lookups and symbol names
    #[arg(long)]
    database: Option<PathBuf>,

    /// Generate PDB file with matched function names
    #[arg(long, requires = "database")]
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

    /// Only dump a specific function by its GUID (hex u64)
    #[arg(short, long, value_parser = parse_hex)]
    function: Option<u64>,
}

/// Show database statistics and section information
#[derive(Parser)]
struct CommandDbInfo {
    /// Path to database file
    #[arg(short, long)]
    database: PathBuf,
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
    // RUST_LOG=binfold=debug
    // RUST_LOG=binfold::warp=trace,binfold::constraint_matcher=debug
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
        Commands::DbInfo(cmd) => command_db_info(cmd),
    }
}

fn command_gen_db(
    CommandGenDb {
        exe: exe_paths,
        database,
        parallel,
    }: CommandGenDb,
) -> Result<()> {
    let multi_progress = indicatif::MultiProgress::new();
    let progress_reporter =
        IndicatifProgressBar::new("Database generation", Some(multi_progress.clone()));

    let mut builder = DatabaseBuilder::new();
    if let Some(p) = parallel {
        builder.parallel(p);
    }

    for path in exe_paths {
        if path.is_dir() {
            builder.add_directory(&path);
        } else {
            builder.add_executable(&path);
        }
    }

    let stats = builder.build_with_progress(&database, &progress_reporter)?;

    multi_progress.clear().unwrap();

    println!("\nSummary:");
    println!("========");
    println!("Database: {}", database.display());
    println!("Total functions: {}", stats.total_functions);
    println!("Unique constraints: {}", stats.unique_constraints);
    println!("Processed files: {}", stats.processed_files);

    Ok(())
}

fn command_analyze(
    CommandAnalyze {
        exe: file,
        database,
        generate_pdb,
    }: CommandAnalyze,
) -> Result<()> {
    use binfold::pdb_analyzer;

    let progress_reporter = IndicatifProgressBar::new("Analyzing", None);

    let analyzer = if let Some(db_path) = database {
        BinfoldAnalyzer::with_database(&file, &db_path)?
    } else {
        BinfoldAnalyzer::new(&file)?
    };

    let result = analyzer.analyze_with_progress(&progress_reporter)?;

    println!("Found {} functions", result.functions.len());

    let matched_count = result
        .database_matches
        .values()
        .filter(|m| m.symbol_name.is_some())
        .count();

    if matched_count > 0 {
        println!("Matched {} functions with database symbols", matched_count);
    }

    if generate_pdb {
        // Get PDB filename from embedded debug info, falling back to exe name with .pdb extension
        let pdb_path = analyzer
            .pe_loader()
            .pdb_info()
            .ok()
            .and_then(|info| {
                let name = info.pdb_path.rsplit(['\\', '/']).next().unwrap();
                (!name.is_empty()).then(|| file.with_file_name(name))
            })
            .unwrap_or_else(|| file.with_extension("pdb"));

        if !pdb_path.exists() || pdb_analyzer::should_replace(&pdb_path).unwrap_or(false) {
            analyzer.generate_pdb(&result, &pdb_path)?;

            let pdb_function_count = result
                .database_matches
                .values()
                .filter(|m| m.symbol_name.is_some())
                .count();

            println!("Generating PDB file at: {}", pdb_path.display());
            println!(
                "PDB file generated successfully with {} functions",
                pdb_function_count
            );
        } else {
            eprintln!(
                "Error: Refusing to overwrite existing PDB file at: {}",
                pdb_path.display()
            );
        }
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
        Box::new(std::iter::once(FunctionGuid::from_digest(function)))
    } else {
        let mut seen = std::collections::HashSet::new();
        let unique: Vec<FunctionGuid> = db.iter_functions().filter(|g| seen.insert(*g)).collect();
        Box::new(unique.into_iter())
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

fn command_db_info(CommandDbInfo { database }: CommandDbInfo) -> Result<()> {
    use std::fs;

    let file = fs::File::open(&database)?;
    let metadata = file.metadata()?;
    let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };
    let db = Db::new(&mmap)?;

    fn format_size(bytes: u64) -> String {
        if bytes >= 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{} B", bytes)
        }
    }

    println!("Database: {}", database.display());
    println!("Total size: {}", format_size(metadata.len()));
    println!("Layers: {}", db.layers().len());

    for (i, layer) in db.layers().iter().enumerate() {
        let s = layer.sections();
        let layer_size = layer.data_len() as u64;

        let header_size = s.strings_offset;
        let strings_size = s.constraints_offset - s.strings_offset;
        let constraints_size = s.constraint_strings_offset - s.constraints_offset;
        let symbol_refs_size = s.function_constraints_offset - s.constraint_strings_offset;
        let func_constraints_size = s.functions_offset - s.function_constraints_offset;
        let functions_size = s.binaries_offset - s.functions_offset;
        let binaries_size = layer_size - s.binaries_offset;

        println!();
        println!("Layer {} ({})", i, format_size(layer_size));
        println!(
            "  {:<22} {:>12} {:>12}  {:<14} Type",
            "Section", "Count", "Size", "Offset"
        );
        println!("  {}", "-".repeat(78));

        let sections: &[(&str, Option<usize>, u64, u64, &str)] = &[
            ("Header", None, header_size, 0, "u64[6]"),
            (
                "Strings",
                Some(layer.strings_count()),
                strings_size,
                s.strings_offset,
                "u32 + (u32 + u8[])[]",
            ),
            (
                "Constraints",
                Some(layer.constraints_count()),
                constraints_size,
                s.constraints_offset,
                "u32 + uuid[]",
            ),
            (
                "Symbol references",
                Some(layer.symbol_references_count()),
                symbol_refs_size,
                s.constraint_strings_offset,
                "u32 + u32[]",
            ),
            (
                "Function constraints",
                Some(layer.function_constraints_count()),
                func_constraints_size,
                s.function_constraints_offset,
                "u32 + (u32 + u32 + u32)[]",
            ),
            (
                "Functions",
                Some(layer.function_count()),
                functions_size,
                s.functions_offset,
                "u32 + (uuid + u32 + u32)[]",
            ),
            (
                "Binaries",
                Some(layer.binary_count()),
                binaries_size,
                s.binaries_offset,
                "u32 + uuid[]",
            ),
        ];

        for (name, count, size, offset, typ) in sections {
            let count_str = count.map_or("-".to_string(), |c| c.to_string());
            println!(
                "  {:<22} {:>12} {:>12}  0x{:08x}     {}",
                name,
                count_str,
                format_size(*size),
                offset,
                typ
            );
        }
    }

    Ok(())
}
