//! PDB function-symbol harvesting from a PE companion `.pdb`.
//!
//! Names come from two PDB streams: the global/public symbol stream carries
//! the canonical mangled name (with full type signature) and wins on
//! collisions; the per-module procedure stream supplies a textual fallback
//! name for file-static / synthetic functions that have no public entry.

use anyhow::{Context, Result};
use pdb::{FallibleIterator, PDB, SymbolData};
use std::collections::HashMap;
use std::path::Path;

use super::{Symbol, SymbolSource};
use crate::binary::Binary;
use crate::mmap_source::MmapSource;

/// A symbol source backed by an opened PDB file.
pub struct PdbSymbols {
    pdb: PDB<'static, MmapSource>,
}

impl PdbSymbols {
    /// Memory-map and parse the PDB at `pdb_path`.
    pub fn open(pdb_path: &Path) -> Result<Self> {
        let mmap_source = MmapSource::new(pdb_path)
            .with_context(|| format!("Failed to memory-map PDB file: {pdb_path:?}"))?;
        let pdb = PDB::open(mmap_source)
            .with_context(|| format!("Failed to parse PDB file: {pdb_path:?}"))?;
        Ok(Self { pdb })
    }
}

impl SymbolSource for PdbSymbols {
    fn label(&self) -> &str {
        "PDB"
    }

    fn function_symbols(self: Box<Self>, bin: &Binary) -> Result<Vec<Symbol>> {
        let mut pdb = self.pdb;
        let address_map = pdb.address_map()?;
        let image_base = bin.image_base();

        // Names come from publics (canonical) with a per-module procedure
        // fallback. Sizes come only from the procedure records (`S_*PROC32`
        // carry a `len`); publics have none. `len_by_addr` is keyed by address
        // so a publicly-named function still picks up the size of the procedure
        // sharing its address. The GUID pipeline ignores size, but the
        // validation harness uses it as ground truth.
        let mut name_by_addr: HashMap<u64, String> = HashMap::new();
        let mut len_by_addr: HashMap<u64, u32> = HashMap::new();

        // Public symbols: canonical mangled name. First-wins guards against
        // ICF/COMDAT folding multiple publics to the same RVA.
        {
            let global_symbols = pdb.global_symbols()?;
            let mut iter = global_symbols.iter();
            while let Ok(Some(symbol)) = iter.next() {
                if let Ok(SymbolData::Public(p)) = symbol.parse()
                    && p.function
                    && let Some(rva) = p.offset.to_rva(&address_map)
                {
                    name_by_addr
                        .entry(image_base + rva.0 as u64)
                        .or_insert_with(|| p.name.to_string().into_owned());
                }
            }
        }

        // Per-module procedures: fill in only addresses the public stream
        // didn't cover (file-static / synthetic functions).
        let dbi = pdb.debug_information()?;
        let mut modules = dbi.modules()?;
        while let Some(module) = modules.next()? {
            if let Ok(Some(module_info)) = pdb.module_info(&module)
                && let Ok(mut module_symbols) = module_info.symbols()
            {
                while let Ok(Some(symbol)) = module_symbols.next() {
                    if let Ok(SymbolData::Procedure(proc)) = symbol.parse()
                        && let Some(rva) = proc.offset.to_rva(&address_map)
                    {
                        let addr = image_base + rva.0 as u64;
                        name_by_addr
                            .entry(addr)
                            .or_insert_with(|| proc.name.to_string().to_string());
                        if proc.len > 0 {
                            len_by_addr.entry(addr).or_insert(proc.len);
                        }
                    }
                }
            }
        }

        Ok(name_by_addr
            .into_iter()
            .map(|(address, name)| Symbol {
                address,
                size: len_by_addr.get(&address).map(|&l| l as u64),
                name,
            })
            .collect())
    }
}
