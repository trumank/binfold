//! Breakpad `.sym` writer for matched-function exports.
//!
//! Format reference:
//! <https://chromium.googlesource.com/breakpad/breakpad/+/HEAD/docs/symbol_files.md>
//!
//! Minimum useful file:
//! ```text
//! MODULE <os> <arch> <id> <module_name>
//! FUNC <hex_addr> <hex_size> 0 <mangled_name>
//! FUNC ...
//! ```
//!
//! We emit only the `MODULE` header and one `FUNC` per matched function: no
//! source lines, no `STACK` records, no `PUBLIC` records. Consumed by
//! Crashpad, Mozilla's `dump_syms`/`symbol-server`, and Firebase Crashlytics.

use std::fmt::Write as _;
use std::io::Write;

use anyhow::Result;

use super::{ExportContext, MatchedFunction, SymbolWriter};
use crate::binary::Arch;

pub struct BreakpadWriter;

impl SymbolWriter for BreakpadWriter {
    fn label(&self) -> &str {
        "Breakpad .sym"
    }

    fn write(
        &self,
        ctx: &ExportContext,
        matches: &[MatchedFunction],
        out: &mut dyn Write,
    ) -> Result<()> {
        let os = "Linux";
        let arch = match ctx.bin.arch()? {
            Arch::Aarch64 => "arm64",
            Arch::X86_64 => "x86_64",
            Arch::X86 => "x86",
        };
        let id = breakpad_id(ctx.bin);
        writeln!(out, "MODULE {os} {arch} {id} {}", ctx.module_name)?;
        for m in matches {
            // `parameter_size` (the 3rd column) is the size of the function's
            // stack-passed parameters. We don't recover that; 0 is the
            // conventional unknown placeholder accepted by every consumer.
            writeln!(out, "FUNC {:x} {:x} 0 {}", m.address, m.size, m.name)?;
        }
        Ok(())
    }
}

/// Format the ELF GNU build-id as a 33-character Breakpad module ID.
///
/// Convention (matching `dump_syms` output): take the first 16 bytes of
/// `.note.gnu.build-id`, treat them as a GUID with the first 4/2/2 byte
/// groups being little-endian integers (so they're byte-swapped on emission),
/// followed by 8 raw bytes, followed by a trailing `"0"` for the "age" field
/// that ELF doesn't have. All uppercase hex.
///
/// If the binary has no build-id, the result is all zeros, which still
/// produces a syntactically valid header.
fn breakpad_id(bin: &crate::binary::Binary) -> String {
    let mut raw_id = [0u8; 16];
    if let Some(id) = bin.build_id() {
        let n = id.len().min(16);
        raw_id[..n].copy_from_slice(&id[..n]);
    }

    let d1 = u32::from_le_bytes(raw_id[0..4].try_into().unwrap());
    let d2 = u16::from_le_bytes(raw_id[4..6].try_into().unwrap());
    let d3 = u16::from_le_bytes(raw_id[6..8].try_into().unwrap());
    let mut s = format!("{d1:08X}{d2:04X}{d3:04X}");
    for b in &raw_id[8..16] {
        let _ = write!(&mut s, "{b:02X}");
    }
    s.push('0');
    s
}
