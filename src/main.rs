use anyhow::Result;
use binfold::db::Db;
use binfold::progress::IndicatifProgressBar;
use binfold::warp::FunctionGuid;
use binfold::{BinfoldAnalyzer, DatabaseBuilder};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

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
    }
}

fn command_gen_db(
    CommandGenDb {
        exe: exe_paths,
        database,
    }: CommandGenDb,
) -> Result<()> {
    let multi_progress = indicatif::MultiProgress::new();
    let progress_reporter =
        IndicatifProgressBar::new("Database generation", Some(multi_progress.clone()));

    let mut builder = DatabaseBuilder::new();

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
        let pdb_path = file.with_extension("pdb");
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
