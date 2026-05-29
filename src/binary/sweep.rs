//! PE32 linear-sweep function discovery.
//!
//! 32-bit PE images carry no exception directory (`.pdata` is an x64 SEH
//! construct), so the normal seed source in [`Binary::find_all_functions`] is
//! empty and recursive descent never starts. This module recovers function
//! starts the way a disassembler bootstraps without symbols: sweep every
//! executable section collecting direct-call targets, size each candidate via
//! the recursive-descent analyzer, then rescan the gaps between known functions
//! for anything the call graph missed (entries reached only through indirect
//! calls, vtables, or jump tables).
//!
//! This is deliberately PE32-only and x86-specific — it decodes with iced
//! directly rather than going through the arch abstraction — and is only
//! entered from the PE32 branch of `find_all_functions`.

use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic};
use iset::IntervalMap;
use std::collections::BTreeMap;
use tracing::{debug, trace};

use super::Binary;
use crate::arch::FunctionAnalysis;
use crate::arch::x86::get_branch_target;

impl Binary {
    /// Discover functions in a PE32 image by linear sweep plus gap scanning.
    /// Returns each function already analyzed (so callers can reuse the result
    /// rather than re-running the analyzer).
    pub(crate) fn find_functions_linear_sweep(
        &self,
        _on_warning: &dyn Fn(&str),
    ) -> Result<Vec<FunctionAnalysis>> {
        let mut function_analysis: BTreeMap<u64, FunctionAnalysis> = BTreeMap::new();
        // Covered address ranges -> entry point (None marks carved-out jump
        // table *data*, so a gap scan won't try to decode a table as code).
        let mut function_map = IntervalMap::<u64, Option<u64>>::new();

        // Executable, non-writable sections only: writable + executable is
        // almost always data (or self-modifying) rather than ordinary code.
        let exec_sections: Vec<(u64, u64)> = self
            .segments_with_perms()
            .filter(|s| s.execute && !s.write && s.size > 0)
            .map(|s| (s.va, s.size))
            .collect();

        // Pass 1: every direct-call target in an executable section is a
        // function start. Size and record each one.
        for &(section_va, section_size) in &exec_sections {
            let Some(data) = self.read_section_clamped(section_va, section_size) else {
                continue;
            };

            debug!(
                start = format!("0x{section_va:x}"),
                size = format!("0x{section_size:x}"),
                "Linear sweep: scanning executable section"
            );

            let mut decoder =
                Decoder::with_ip(self.bitness(), data, section_va, DecoderOptions::NONE);
            let mut candidates = Vec::new();
            while decoder.can_decode() {
                let instruction = decoder.decode();
                if instruction.flow_control() == FlowControl::Call
                    && let Some(target) = get_branch_target(&instruction)
                {
                    candidates.push(target);
                }
            }

            for func_start in candidates {
                self.record_function(func_start, None, &mut function_map, &mut function_analysis);
            }
        }

        // Pass 2: rescan the gaps between discovered functions for entries the
        // call graph never reached.
        for &(section_va, section_size) in &exec_sections {
            let section_end = section_va + section_size;

            let mut gaps = Vec::new();
            let mut last_end = section_va;
            for interval in function_map.intervals(section_va..section_end) {
                if interval.start > last_end {
                    gaps.push(last_end..interval.start);
                }
                last_end = last_end.max(interval.end);
            }
            if last_end < section_end {
                gaps.push(last_end..section_end);
            }

            for gap in gaps {
                let gap_size = gap.end - gap.start;
                let Some(gap_data) = self.read_section_clamped(gap.start, gap_size) else {
                    continue;
                };

                trace!(
                    start = format!("0x{:x}", gap.start),
                    end = format!("0x{:x}", gap.end),
                    "Linear sweep: scanning gap"
                );

                let mut decoder =
                    Decoder::with_ip(self.bitness(), gap_data, gap.start, DecoderOptions::NONE);
                while decoder.can_decode() {
                    let instruction = decoder.decode();
                    let ip = instruction.ip();

                    // Skip obvious non-starts (padding / invalid bytes).
                    if instruction.mnemonic() == Mnemonic::INVALID
                        || instruction.flow_control() == FlowControl::Interrupt
                    {
                        continue;
                    }

                    // Don't restart inside a function we already found.
                    if function_map.has_overlap(ip..ip + 1) {
                        continue;
                    }

                    self.record_function(
                        ip,
                        Some(gap.end),
                        &mut function_map,
                        &mut function_analysis,
                    );
                }
            }
        }

        let functions: Vec<FunctionAnalysis> = function_analysis.into_values().collect();
        tracing::info!(
            functions = functions.len(),
            "PE32 linear sweep discovery complete"
        );
        Ok(functions)
    }

    /// Analyze the candidate at `addr` and, if it doesn't overlap an existing
    /// function (and stays within `max_end` when scanning a gap), record it and
    /// carve out any jump-table data it references.
    fn record_function(
        &self,
        addr: u64,
        max_end: Option<u64>,
        function_map: &mut IntervalMap<u64, Option<u64>>,
        function_analysis: &mut BTreeMap<u64, FunctionAnalysis>,
    ) {
        if function_map.has_overlap(addr..addr + 1) {
            return;
        }

        let func = match self.analyze_function(addr) {
            Ok(func) => func,
            Err(e) => {
                trace!(
                    address = format!("0x{addr:x}"),
                    error = %e,
                    "Linear sweep: candidate failed to analyze"
                );
                return;
            }
        };

        let func_end = addr + func.size as u64;
        if func.size == 0
            || max_end.is_some_and(|end| func_end > end)
            || function_map.has_overlap(addr..func_end)
        {
            return;
        }

        debug!(
            start = format!("0x{addr:x}"),
            end = format!("0x{func_end:x}"),
            size = format!("0x{:x}", func.size),
            "Linear sweep: function discovered"
        );

        for table in &func.jump_tables {
            if table.end > table.start && !function_map.has_overlap(table.start..table.end) {
                function_map.insert(table.start..table.end, None);
            }
        }
        function_map.insert(addr..func_end, Some(addr));
        function_analysis.insert(func.entry_point, func);
    }

    /// Read up to `size` bytes at `va`, clamped to the bytes actually present
    /// in the file image (virtual size can exceed raw size). Returns `None` if
    /// the address can't be mapped or no bytes are available.
    fn read_section_clamped(&self, va: u64, size: u64) -> Option<&[u8]> {
        let rva = va.checked_sub(self.image_base())?;
        let offset = self.rva_to_file_offset(rva).ok()?;
        let available = self.raw_bytes().len().checked_sub(offset)?;
        let len = (size as usize).min(available);
        if len == 0 {
            return None;
        }
        self.read_at_va(va, len).ok()
    }
}
