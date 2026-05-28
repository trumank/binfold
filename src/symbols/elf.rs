//! ELF function-symbol recovery.
//!
//! Prefers the richest available table:
//!
//!   1. `.symtab`: full developer names, present in un-stripped builds.
//!   2. `.dynsym`: exported names, survives `strip`.
//!   3. A `PT_DYNAMIC`-driven walk for binaries whose section header table
//!      has been stripped (shipping Android `.so`s), where `object`'s
//!      section-driven symbol iterators come back empty even though the
//!      dynamic symbol table is intact.
//!
//! Steps 1-2 go through `object`'s high-level iterators. Step 3 leans on
//! `object`'s typed primitives
//! ([`SegmentHeader::dynamic`](object::read::elf::ProgramHeader::dynamic),
//! [`GnuHashTable`]/[`HashTable`], [`Sym`]) so there is no raw offset
//! arithmetic to keep in sync with the ELF spec.

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use object::elf::{
    DT_GNU_HASH, DT_HASH, DT_NULL, DT_STRSZ, DT_STRTAB, DT_SYMTAB, FileHeader64, SHN_UNDEF,
    STT_FUNC, Sym64,
};
use object::read::StringTable;
use object::read::elf::{Dyn, GnuHashTable, HashTable, ProgramHeader, Sym};
use object::{Endianness, Object, ObjectSymbol, SymbolKind, SymbolScope};

use super::{Symbol, SymbolSource};
use crate::binary::Binary;

/// Function symbols read from an ELF image's own tables.
pub struct ElfSymbols;

impl SymbolSource for ElfSymbols {
    fn label(&self) -> &str {
        ".symtab/.dynsym"
    }

    fn function_symbols(self: Box<Self>, bin: &Binary) -> Result<Vec<Symbol>> {
        function_symbols(bin)
    }
}

/// Free-function form (no trait object) for direct callers.
pub fn function_symbols(bin: &Binary) -> Result<Vec<Symbol>> {
    let mut out = Vec::new();
    match bin.object_file() {
        object::File::Elf64(elf) => {
            collect_from_iter(elf.symbols(), &mut out);
            if out.is_empty() {
                collect_from_iter(elf.dynamic_symbols(), &mut out);
            }
            if out.is_empty() {
                out = dynamic_function_symbols(bin)?;
            }
        }
        object::File::Elf32(elf) => {
            collect_from_iter(elf.symbols(), &mut out);
            if out.is_empty() {
                collect_from_iter(elf.dynamic_symbols(), &mut out);
            }
            // 32-bit isn't an in-scope target; no PT_DYNAMIC fallback.
        }
        _ => {}
    }
    Ok(out)
}

/// Collect defined function symbols from an ELF symbol iterator (`.symtab` or
/// `.dynsym`).
///
/// Keeps only text, defined, non-zero-size symbols, deduplicated by address.
/// When several names alias the same address (ICF folding, `.symtab`/`.dynsym`
/// overlap), a global binding is preferred over a local one so ground-truth
/// names stay stable.
fn collect_from_iter<'data, S, I>(syms: I, out: &mut Vec<Symbol>)
where
    S: ObjectSymbol<'data>,
    I: Iterator<Item = S>,
{
    // address -> index into `out`, alongside whether that entry is global.
    let mut seen: HashMap<u64, usize> = HashMap::new();
    let mut is_global: Vec<bool> = Vec::new();
    for sym in syms {
        if sym.kind() != SymbolKind::Text || sym.is_undefined() || sym.size() == 0 {
            continue;
        }
        let addr = sym.address();
        let global = matches!(sym.scope(), SymbolScope::Linkage | SymbolScope::Dynamic);
        match seen.get(&addr) {
            Some(&idx) => {
                // Upgrade a previously-recorded local alias to a global name.
                if global && !is_global[idx] {
                    out[idx].size = Some(sym.size());
                    out[idx].name = sym.name().unwrap_or("<bad-utf8>").to_string();
                    is_global[idx] = true;
                }
            }
            None => {
                seen.insert(addr, out.len());
                is_global.push(global);
                out.push(Symbol {
                    address: addr,
                    size: Some(sym.size()),
                    name: sym.name().unwrap_or("<bad-utf8>").to_string(),
                });
            }
        }
    }
}

/// Recover ELF64 dynamic function symbols by walking `PT_DYNAMIC` directly,
/// for section-header-stripped images where `object`'s section-driven
/// iterators are empty.
fn dynamic_function_symbols(bin: &Binary) -> Result<Vec<Symbol>> {
    let object::File::Elf64(elf) = bin.object_file() else {
        return Ok(vec![]);
    };
    let endian = elf.endian();
    let data = bin.raw_bytes();
    let image_base = bin.image_base();

    // The PT_DYNAMIC entry array, typed via `object`.
    let Some(dynamic) = elf
        .elf_program_headers()
        .iter()
        .find_map(|ph| ph.dynamic(endian, data).ok().flatten())
    else {
        return Ok(vec![]);
    };

    // Pull the dynamic tags we need. Values are virtual addresses (DT_*_VA) or
    // sizes (DT_STRSZ).
    let (mut symtab_va, mut strtab_va, mut strsz, mut hash_va, mut gnu_hash_va) =
        (None, None, None, None, None);
    for d in dynamic {
        let Some(tag) = d.tag32(endian) else { continue };
        let val = d.d_val(endian);
        match tag {
            DT_NULL => break,
            DT_SYMTAB => symtab_va = Some(val),
            DT_STRTAB => strtab_va = Some(val),
            DT_STRSZ => strsz = Some(val),
            DT_HASH => hash_va = Some(val),
            DT_GNU_HASH => gnu_hash_va = Some(val),
            _ => {}
        }
    }
    let (Some(symtab_va), Some(strtab_va), Some(strsz)) = (symtab_va, strtab_va, strsz) else {
        bail!("dynamic table missing DT_SYMTAB/STRTAB/STRSZ");
    };

    let to_off = |va: u64| bin.rva_to_file_offset(va.saturating_sub(image_base));
    let symtab_off = to_off(symtab_va)?;
    let strtab_off = to_off(strtab_va)?;

    let strtab_bytes = data
        .get(strtab_off..strtab_off + strsz as usize)
        .ok_or_else(|| anyhow!("string table out of bounds"))?;
    let strings = StringTable::new(strtab_bytes, 0, strsz);

    // Symbol count. DT_HASH's `nchain` is the exact entry count; DT_GNU_HASH
    // requires walking the hash chains (the common case on modern Android,
    // which ships only GNU hash). Fall back to the SYMTAB-precedes-STRTAB
    // adjacency convention only when neither hash table is present.
    let count: usize = if let Some(hash_va) = hash_va {
        let off = to_off(hash_va)?;
        let tail = data
            .get(off..)
            .ok_or_else(|| anyhow!("DT_HASH out of bounds"))?;
        HashTable::<FileHeader64<Endianness>>::parse(endian, tail)
            .map_err(|e| anyhow!("parsing DT_HASH: {e}"))?
            .symbol_table_length() as usize
    } else if let Some(gnu_hash_va) = gnu_hash_va {
        let off = to_off(gnu_hash_va)?;
        let tail = data
            .get(off..)
            .ok_or_else(|| anyhow!("DT_GNU_HASH out of bounds"))?;
        GnuHashTable::<FileHeader64<Endianness>>::parse(endian, tail)
            .map_err(|e| anyhow!("parsing DT_GNU_HASH: {e}"))?
            .symbol_table_length(endian)
            .ok_or_else(|| anyhow!("DT_GNU_HASH yielded no symbol count"))? as usize
    } else if strtab_off > symtab_off {
        (strtab_off - symtab_off) / std::mem::size_of::<Sym64<Endianness>>()
    } else {
        bail!(
            "no DT_HASH/DT_GNU_HASH and STRTAB does not follow SYMTAB; cannot size dynamic symbol table"
        );
    };

    let sym_bytes = data
        .get(symtab_off..)
        .ok_or_else(|| anyhow!("symbol table out of bounds"))?;
    let (syms, _) = object::slice_from_bytes::<Sym64<Endianness>>(sym_bytes, count)
        .map_err(|_| anyhow!("dynamic symbol table truncated"))?;

    let mut out = Vec::with_capacity(count);
    for sym in syms {
        if sym.st_type() != STT_FUNC || sym.st_shndx(endian) == SHN_UNDEF {
            continue;
        }
        let size = sym.st_size(endian);
        if size == 0 {
            continue;
        }
        let name = match sym.name(endian, strings) {
            Ok(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            Err(_) => continue,
        };
        if name.is_empty() {
            continue;
        }
        out.push(Symbol {
            address: sym.st_value(endian),
            size: Some(size),
            name,
        });
    }
    Ok(out)
}
