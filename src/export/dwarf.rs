//! DWARF companion writer for matched-function exports.
//!
//! Produces an ELF debug-companion file (the `objcopy --only-keep-debug`
//! shape, minus the per-section stubs we'd need for `.gnu_debuglink` to kick
//! in automatically) containing one `DW_TAG_subprogram` per matched function
//! with `DW_AT_name` + `DW_AT_low_pc` + `DW_AT_high_pc`.
//!
//! Consumers:
//!   * Binary Ninja: `File > Open with Options > Debug File`.
//!   * gdb / lldb: `gdb -s /path/to/debug binary`, or via `.gnu_debuglink` /
//!     build-id symbol-store discovery.
//!   * IDA / Ghidra: same companion file pattern.
//!
//! The `.note.gnu.build-id` section is copied from the source binary so
//! consumers that key on build-id will associate this file with the original.

use std::io::Write;

use anyhow::Result;
use gimli::write::{Address, AttributeValue, DwarfUnit, EndianVec, Sections};
use gimli::{Encoding, Format, LittleEndian};
use object::write::{Object, SectionKind};
use object::{Architecture, BinaryFormat, Endianness};

use super::{ExportContext, MatchedFunction, SymbolWriter};
use crate::binary::Arch;

pub struct DwarfWriter;

impl SymbolWriter for DwarfWriter {
    fn label(&self) -> &str {
        "DWARF debug companion (ELF)"
    }

    fn write(
        &self,
        ctx: &ExportContext,
        matches: &[MatchedFunction],
        out: &mut dyn Write,
    ) -> Result<()> {
        let bin = ctx.bin;
        let arch = match bin.arch()? {
            Arch::Aarch64 => Architecture::Aarch64,
            Arch::X86_64 => Architecture::X86_64,
            Arch::X86 => Architecture::I386,
        };
        let address_size: u8 = match bin.arch()? {
            Arch::X86 => 4,
            _ => 8,
        };

        // DWARF 4 / 32-bit format is the widely-compatible default.
        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size,
        };

        let mut dwarf = DwarfUnit::new(encoding);

        // CU root: just enough metadata that consumers display something
        // sensible. No source files / line numbers (not recoverable here).
        let cu_name = dwarf
            .strings
            .add(format!("binfold-symbols/{}", ctx.module_name).into_bytes());
        let producer = dwarf.strings.add(b"binfold"[..].to_vec());
        let root = dwarf.unit.root();
        {
            let die = dwarf.unit.get_mut(root);
            die.set(gimli::DW_AT_name, AttributeValue::StringRef(cu_name));
            die.set(gimli::DW_AT_producer, AttributeValue::StringRef(producer));
            // Mark C++ so consumers know names may be mangled.
            die.set(
                gimli::DW_AT_language,
                AttributeValue::Language(gimli::DW_LANG_C_plus_plus),
            );
        }

        // One DW_TAG_subprogram per matched function. StringRef (.debug_str
        // pool) dedups repeated names and keeps each DIE small.
        //
        // Track the bounding address range to declare it on the CU root below.
        // Without CU bounds, address-to-symbol resolvers (addr2line,
        // llvm-symbolizer) can't pick a CU to scan and return "??" for every
        // lookup, even though the subprogram entries are perfectly valid.
        let mut cu_low: u64 = u64::MAX;
        let mut cu_high: u64 = 0;
        for m in matches {
            let name_ref = dwarf.strings.add(m.name.as_bytes().to_vec());
            let sp = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
            let die = dwarf.unit.get_mut(sp);
            // The database carries Itanium-ABI mangled C++ names ("_ZN...").
            // DWARF convention is DW_AT_name = source identifier,
            // DW_AT_linkage_name = ABI mangled. Setting both to the mangled
            // form lets BN demangle the linkage_name for display while still
            // satisfying consumers that require DW_AT_name.
            die.set(gimli::DW_AT_name, AttributeValue::StringRef(name_ref));
            die.set(
                gimli::DW_AT_linkage_name,
                AttributeValue::StringRef(name_ref),
            );
            die.set(
                gimli::DW_AT_low_pc,
                AttributeValue::Address(Address::Constant(m.address)),
            );
            // DW_AT_high_pc with form DW_FORM_data* (Udata) is an offset from
            // low_pc per DWARF 4. That's what `size` is.
            die.set(gimli::DW_AT_high_pc, AttributeValue::Udata(m.size));
            // These are exported public-ish symbols, not file-static.
            die.set(gimli::DW_AT_external, AttributeValue::Flag(true));
            cu_low = cu_low.min(m.address);
            cu_high = cu_high.max(m.address + m.size);
        }

        // CU bounds (loose single-range cover).
        if cu_low < cu_high {
            let die = dwarf.unit.get_mut(root);
            die.set(
                gimli::DW_AT_low_pc,
                AttributeValue::Address(Address::Constant(cu_low)),
            );
            die.set(
                gimli::DW_AT_high_pc,
                AttributeValue::Udata(cu_high - cu_low),
            );
        }

        // Serialize DWARF into per-section byte buffers.
        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections)?;

        // Wrap into an ELF container. object's high-level writer produces an
        // ET_REL file; fine for debug companions since consumers care about
        // the debug sections, not e_type.
        let mut obj = Object::new(BinaryFormat::Elf, arch, Endianness::Little);
        sections.for_each(|id, w| -> Result<(), anyhow::Error> {
            let data = w.slice();
            if data.is_empty() {
                return Ok(());
            }
            let sid = obj.add_section(vec![], id.name().as_bytes().to_vec(), SectionKind::Debug);
            obj.set_section_data(sid, data.to_vec(), 1);
            Ok(())
        })?;

        // Mirror the source binary's GNU build-id so the companion can be
        // discovered via gdb's `/usr/lib/debug/.build-id/XX/YYYYYY.debug`
        // convention and BN's auto-pairing logic.
        if let Some(build_id) = bin.build_id() {
            let note = build_note_gnu_build_id(build_id);
            let sid = obj.add_section(vec![], b".note.gnu.build-id".to_vec(), SectionKind::Note);
            obj.set_section_data(sid, note, 4);
        }

        let bytes = obj.write()?;
        out.write_all(&bytes)?;
        Ok(())
    }
}

/// Build a `SHT_NOTE` section payload for `NT_GNU_BUILD_ID`.
///
/// Layout (ELF Note section format):
/// ```text
/// namesz : u32 = 4         ("GNU\0")
/// descsz : u32 = build_id.len()
/// type   : u32 = 3         (NT_GNU_BUILD_ID)
/// name   : bytes           "GNU\0", padded to 4-byte alignment
/// desc   : bytes           build_id, padded to 4-byte alignment
/// ```
fn build_note_gnu_build_id(build_id: &[u8]) -> Vec<u8> {
    const NT_GNU_BUILD_ID: u32 = 3;
    let mut buf = Vec::with_capacity(16 + build_id.len() + 4);
    buf.extend_from_slice(&4u32.to_le_bytes());
    buf.extend_from_slice(&(build_id.len() as u32).to_le_bytes());
    buf.extend_from_slice(&NT_GNU_BUILD_ID.to_le_bytes());
    buf.extend_from_slice(b"GNU\0");
    buf.extend_from_slice(build_id);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf
}
