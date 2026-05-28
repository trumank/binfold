//! Function-symbol sources for gen-db name harvesting.
//!
//! gen-db needs an `address -> name` map to label functions before WARP
//! analysis. *Where* that map comes from is format-specific (a PDB companion
//! on PE, the `.symtab`/`.dynsym` on ELF), but the downstream pipeline
//! ([`crate::build_pipeline`]) is identical regardless of source.
//!
//! This module is the format-neutral seam, mirroring what `arch::` and
//! `binary::` did for decoding and loading. A [`SymbolSource`] trait abstracts
//! "give me this binary's named functions"; [`resolve_symbol_source`] picks
//! the best available source for a loaded binary by availability, not a
//! hardcoded format branch in the caller. New sources (a PE export table,
//! Mach-O, sidecar map files) slot in behind the trait without touching
//! gen-db.

use std::path::Path;

use anyhow::{Result, bail};

use crate::binary::Binary;

pub mod elf;
pub mod pdb;

/// One named function recovered from a symbol source.
///
/// `size` is populated when the source knows it (ELF symbol tables carry
/// `st_size`; PDB leaves it `None`). It is advisory only (the GUID pipeline
/// recomputes each function's real extent via recursive descent), carried for
/// diagnostics and future tooling.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub address: u64,
    pub size: Option<u64>,
    pub name: String,
}

/// A provider of function `(address, name)` pairs for one loaded binary.
///
/// `function_symbols` consumes the source (`self: Box<Self>`) because some
/// backends (notably PDB) need exclusive access to their underlying stream to
/// walk it once; a source is resolved, used once, and dropped.
pub trait SymbolSource {
    /// Short human label for diagnostics (e.g. `"PDB"`, `".symtab/.dynsym"`).
    fn label(&self) -> &str;

    /// Enumerate defined function symbols. May legitimately return empty
    /// (e.g. a fully stripped binary), which the caller treats as "no names".
    fn function_symbols(self: Box<Self>, bin: &Binary) -> Result<Vec<Symbol>>;
}

/// Pick the best available function-symbol source for `bin`.
///
/// Selection is by availability rather than a hardcoded `is_pe()` fork in the
/// caller: a PE image looks for its sibling `.pdb`; everything else (ELF
/// today) reads its own symbol/dynamic tables. `exe_path` is the on-disk path
/// of the loaded binary, used to locate companion files.
pub fn resolve_symbol_source(bin: &Binary, exe_path: &Path) -> Result<Box<dyn SymbolSource>> {
    if bin.is_pe() {
        let pdb_path = exe_path.with_extension("pdb");
        if !pdb_path.exists() {
            bail!(
                "{}: PE image has no companion {} for symbol harvesting",
                exe_path.display(),
                pdb_path.display()
            );
        }
        Ok(Box::new(pdb::PdbSymbols::open(&pdb_path)?))
    } else {
        Ok(Box::new(elf::ElfSymbols))
    }
}
