//! Matched-function export: the "symbol writing" side.
//!
//! Mirror of the [`crate::symbols`] read side: where that module abstracts
//! getting `(address, name)` pairs out of a binary, this one abstracts
//! writing matched functions out to the various debugger/symbolication
//! formats. A [`SymbolWriter`] trait unifies the formats and
//! [`OutputFormat::from_extension`] is the single place output kind is chosen,
//! so the CLI dispatches in one spot instead of a per-format `match`.
//!
//! Formats:
//!   * Breakpad `.sym` (Crashpad / minidump-stackwalk / Crashlytics)
//!   * DWARF companion `.debug`/`.dwarf` (gdb/lldb/BN/IDA/Ghidra)
//!   * PDB `.pdb` (Windows / Binary Ninja)
//!
//! Every writer streams bytes into a `&mut dyn Write`, so the same registry
//! serves both the `--output <file>` path and the `--generate-pdb` flag.

use std::io::Write;

use anyhow::Result;

use crate::binary::Binary;

pub mod breakpad;
pub mod dwarf;
pub mod pdb;

/// One matched function to emit. `name` is borrowed from the match table; the
/// writers never need it owned.
#[derive(Clone, Copy)]
pub struct MatchedFunction<'a> {
    pub address: u64,
    pub size: u64,
    pub name: &'a str,
}

/// Per-export context shared by every writer: the analyzed binary (for arch,
/// image base, build-id, PE sections) and the module name a debugger will
/// associate the symbols with.
pub struct ExportContext<'a> {
    pub bin: &'a Binary,
    pub module_name: &'a str,
}

/// A matched-function export format.
pub trait SymbolWriter {
    /// Short human label for diagnostics (e.g. `"Breakpad .sym"`).
    fn label(&self) -> &str;

    /// Serialize `matches` into `out` in this format.
    fn write(
        &self,
        ctx: &ExportContext,
        matches: &[MatchedFunction],
        out: &mut dyn Write,
    ) -> Result<()>;
}

/// Output formats selectable by output-file extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Breakpad,
    Dwarf,
    Pdb,
}

impl OutputFormat {
    /// Map a (case-insensitive) file extension to a format, or `None` if
    /// unrecognized.
    pub fn from_extension(ext: &str) -> Option<Self> {
        Some(match ext.to_ascii_lowercase().as_str() {
            "sym" => Self::Breakpad,
            "debug" | "dwarf" => Self::Dwarf,
            "pdb" => Self::Pdb,
            _ => return None,
        })
    }

    /// The writer implementation for this format.
    pub fn writer(self) -> Box<dyn SymbolWriter> {
        match self {
            Self::Breakpad => Box::new(breakpad::BreakpadWriter),
            Self::Dwarf => Box::new(dwarf::DwarfWriter),
            Self::Pdb => Box::new(pdb::PdbWriter),
        }
    }

    /// Human list of accepted extensions, for error messages.
    pub const SUPPORTED: &'static str =
        ".sym (Breakpad), .debug/.dwarf (DWARF companion), .pdb (PDB)";
}
