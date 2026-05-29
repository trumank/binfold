//! x86 / x86-64 recursive-descent analyzer and WARP per-block byte masker.
//!
//! The masker decodes a basic block with iced-x86 and emits the WARP bytes:
//! register-to-self NOPs are dropped, relocatable / RIP-relative instructions
//! are zeroed, everything else is copied verbatim. The hashing of the
//! resulting byte stream lives in `warp`. The analyzer ([`X86Isa`]) walks
//! reachable instructions from a function entry point via recursive descent.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::ops::Range;

use anyhow::{Result, bail};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use tracing::{debug, trace};

use super::BlockMasker;
use crate::arch::{
    BlockBound, DataReference, FunctionAnalysis, FunctionCall, InstructionSet, JumpTable,
    MemoryView,
};

/// WARP byte masker for x86 / x86-64. `bitness` is what the iced-x86 decoder
/// consumes (32 or 64).
pub struct X86Masker {
    bitness: u32,
    /// Section VA ranges, `Some` only for PE32. 32-bit x86 embeds *absolute*
    /// (relocated) addresses as immediates and displacements rather than the
    /// RIP-relative form the 64-bit path already masks; this drives the extra
    /// masking. `None` for x86-64 and ELF-i386, where behaviour is unchanged.
    pe32_sections: Option<std::sync::Arc<[Range<u64>]>>,
}

impl X86Masker {
    pub fn new(bitness: u32) -> Self {
        Self {
            bitness,
            pe32_sections: None,
        }
    }

    /// Masker for a PE32 image. `sections` are the image's section VA ranges
    /// (see [`crate::binary::Binary::section_ranges`]); they let the masker
    /// distinguish a relocated absolute address from a plain constant.
    pub fn new_pe32(sections: std::sync::Arc<[Range<u64>]>) -> Self {
        Self {
            bitness: 32,
            pe32_sections: Some(sections),
        }
    }
}

impl BlockMasker for X86Masker {
    fn mask(&mut self, raw: &[u8], va: u64, bounds: Range<u64>) -> Vec<u8> {
        let raw_bytes = raw;
        let base = va;
        let function_bounds = bounds;

        let mut bytes = Vec::new();

        let mut decoder = Decoder::new(self.bitness, raw_bytes, DecoderOptions::NONE);
        decoder.set_ip(base);

        debug!(
            target: "binfold::warp::guid",
            "Starting instruction processing for GUID"
        );

        while decoder.can_decode() {
            let start = (decoder.ip() - base) as usize;
            let instruction = decoder.decode();
            let end = (decoder.ip() - base) as usize;
            let instr_bytes = &raw_bytes[start..end];

            // Skip instructions that set a register to itself (if they're effectively NOPs)
            if is_register_to_itself_nop(&instruction) {
                trace!(
                    target: "binfold::warp::guid",
                    addr = format!("0x{:x}", instruction.ip()),
                    instruction = %instruction,
                    "Skipping register-to-itself NOP"
                );
                continue;
            }

            // Get instruction bytes, zeroing out relocatable instructions
            if is_relocatable_instruction(
                &instruction,
                function_bounds.clone(),
                self.pe32_sections.as_deref(),
            ) {
                // Zero out relocatable instructions
                bytes.extend(vec![0u8; instr_bytes.len()]);
                trace!(
                    target: "binfold::warp::guid",
                    addr = format!("0x{:x}", instruction.ip()),
                    instruction = %instruction,
                    bytes = format!("{:02x?}", instr_bytes),
                    "Zeroing relocatable instruction"
                );
            } else {
                // Use actual instruction bytes
                bytes.extend_from_slice(instr_bytes);
                trace!(
                    target: "binfold::warp::guid",
                    addr = format!("0x{:x}", instruction.ip()),
                    instruction = %instruction,
                    bytes = format!("{:02x?}", instr_bytes),
                    "Keeping instruction bytes"
                );
            }
        }

        bytes
    }
}

pub(crate) fn get_branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction.op_kind(0) {
        OpKind::NearBranch16 => Some(instruction.near_branch16() as u64),
        OpKind::NearBranch32 => Some(instruction.near_branch32() as u64),
        OpKind::NearBranch64 => Some(instruction.near_branch64()),
        _ => None,
    }
}

fn is_register_to_itself_nop(instruction: &Instruction) -> bool {
    if instruction.mnemonic() != Mnemonic::Mov {
        return false;
    }

    if instruction.op_count() != 2 {
        return false;
    }

    // Check if both operands are the same register
    if let (OpKind::Register, OpKind::Register) = (instruction.op_kind(0), instruction.op_kind(1)) {
        let reg0 = instruction.op_register(0);
        let reg1 = instruction.op_register(1);

        // For x86_64, mov edi, edi is NOT removed (implicit extension)
        // For x86, it would be removed
        if reg0 == reg1 && !has_implicit_extension(reg0) {
            return true;
        }
    }

    false
}

fn has_implicit_extension(reg: Register) -> bool {
    // In x86_64, 32-bit register operations zero-extend to 64 bits
    matches!(
        reg,
        Register::EAX
            | Register::EBX
            | Register::ECX
            | Register::EDX
            | Register::EDI
            | Register::ESI
            | Register::EBP
            | Register::ESP
            | Register::R8D
            | Register::R9D
            | Register::R10D
            | Register::R11D
            | Register::R12D
            | Register::R13D
            | Register::R14D
            | Register::R15D
    )
}

/// Decide whether an instruction's bytes must be zeroed for the WARP GUID.
///
/// `pe32_sections` is `Some` only for PE32 images; when present, the extra
/// PE32-specific checks below run. For x86-64 and ELF-i386 it is `None` and
/// this function behaves exactly as before (the emitted bytes are identical).
fn is_relocatable_instruction(
    instruction: &Instruction,
    function_bounds: Range<u64>,
    pe32_sections: Option<&[Range<u64>]>,
) -> bool {
    // Check for direct calls - but only forward calls are relocatable
    if instruction.mnemonic() == Mnemonic::Call && instruction.op_count() > 0 {
        match instruction.op_kind(0) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                // All direct calls are relocatable
                return true;
            }
            _ => {}
        }
    }

    // Check for tail call jumps (unconditional jumps that likely go to other functions)
    if instruction.mnemonic() == Mnemonic::Jmp && instruction.op_count() > 0 {
        match instruction.op_kind(0) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                // Check if jump target is outside function bounds
                if let Some(target) = get_branch_target(instruction)
                    && !function_bounds.contains(&target)
                {
                    return true;
                }
            }
            _ => {}
        }
    }

    // Check other RIP-relative memory operands (for non-MOV/LEA instructions)
    for i in 0..instruction.op_count() {
        if instruction.op_kind(i) == OpKind::Memory {
            // Check if it's RIP-relative (no base register, or RIP as base)
            if instruction.memory_base() == Register::RIP {
                return true;
            }

            // Also check for displacement-only addressing (no base, no index)
            // BUT exclude segment-relative addressing (GS, FS, etc)
            if instruction.memory_base() == Register::None
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() != 0
                && instruction.segment_prefix() == Register::None
            {
                return true;
            }
        }
    }

    // PE32-only: 32-bit x86 references absolute addresses the loader relocates,
    // either as 32-bit immediates (`push offset X`, `mov reg, imm32`) or as
    // displacements inside indexed memory operands (`mov eax, [esi*4 + table]`)
    // that the displacement-only check above doesn't catch. Zero any operand
    // whose value lands inside a mapped section so the GUID stays stable across
    // relocations. Gated on `Some` so x86-64 / ELF-i386 are unaffected.
    if let Some(sections) = pe32_sections {
        for i in 0..instruction.op_count() {
            match instruction.op_kind(i) {
                OpKind::Immediate32 => {
                    if in_section(sections, instruction.immediate32() as u64) {
                        return true;
                    }
                }
                OpKind::Memory => {
                    if instruction.segment_prefix() == Register::None
                        && in_section(sections, instruction.memory_displacement64())
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }

    false
}

/// True if `va` falls within any of the image's section VA ranges.
fn in_section(sections: &[Range<u64>], va: u64) -> bool {
    sections.iter().any(|r| r.contains(&va))
}

/// x86 / x86-64 recursive-descent function analyzer backend.
pub struct X86Isa;

impl InstructionSet for X86Isa {
    fn analyze_function(&self, mem: &dyn MemoryView, va: u64) -> Result<FunctionAnalysis> {
        let mut analysis = FunctionAnalysis {
            entry_point: va,
            ..Default::default()
        };

        let tail_call_threshold = 0x50;

        let start_offset = mem.rva_to_file_offset(va.saturating_sub(mem.image_base()))?;
        let file_data = mem.raw_bytes();
        let available = file_data.len().saturating_sub(start_offset);

        // Clamp the scan window to the FDE end when `.eh_frame` provides one
        // (ELF). Descent past the real end - through a tail-call `jmp` into the
        // adjacent function, or a non-returning call that falls through - is the
        // dominant source of size over-estimation.
        let fde_end = mem.function_size_hint(va);
        // FDE-bounded functions may legitimately exceed 64 KiB (generated
        // static-init / registration thunks), and the FDE end clamps them
        // precisely, so a larger ceiling is safe there. Without an FDE end (PE
        // today, or a start reached only by call-graph descent) `max_scan` is
        // the sole backstop against runaway descent - keep the conservative
        // 64 KiB so a tail-call the distance heuristic misjudges can't balloon.
        let max_scan: usize = if fde_end.is_some() { 0x40000 } else { 0x10000 };
        let fde_cap = fde_end.map(|end| (end - va) as usize).unwrap_or(max_scan);
        let scan_size = max_scan.min(fde_cap).min(available);

        if scan_size == 0 {
            bail!("No bytes available to scan");
        }

        let bytes = &file_data[start_offset..start_offset + scan_size];

        debug!(
            target: "binfold::arch::size",
            start = format!("0x{va:x}"),
            scan_range = format!("0x{scan_size:x}"),
            "Scanning function size"
        );

        // First decode all instructions in the scan range
        // let mut all_instructions = std::collections::BTreeMap::new();
        let bitness = mem.bitness();
        let mut decoder = Decoder::with_ip(bitness, bytes, va, DecoderOptions::NONE);

        // Now do recursive descent to find all reachable instructions
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut tailcall_queue = VecDeque::new();
        let mut block_intervals: BTreeSet<BlockBound> = Default::default();

        queue.push_back((va, None));

        let mut max_address = va;

        block_intervals.insert(BlockBound::Start(va));

        debug!(
            target: "binfold::arch::size",
            start = format!("0x{va:x}"),
            "Starting recursive descent"
        );

        while let Some((ip, from)) = queue.pop_front() {
            trace!(
                target: "binfold::arch::size",
                at = format!("0x{ip:x}"),
                from = from.map(|f| format!("0x{f:x}")),
                "Disassembling"
            );

            if ip
                .checked_sub(va)
                .and_then(|pos| decoder.set_position(pos as usize).ok())
                .is_some()
            {
                decoder.set_ip(ip);
            } else {
                trace!(
                    target: "binfold::arch::size",
                    address = format!("0x{ip:x}"),
                    "Out of function bounds"
                );
                continue;
            }
            while decoder.can_decode() && !visited.contains(&decoder.ip()) {
                let instruction = decoder.decode();
                let ip = instruction.ip();
                visited.insert(ip);

                trace!(
                    target: "binfold::arch::size",
                    offset = format!("0x{:<5x}", ip - va),
                    address = format!("0x{:x}", ip),
                    instruction = %instruction,
                    flow_control = ?instruction.flow_control(),
                    "Instruction"
                );

                // Update max address
                let next_ip = decoder.ip();
                if next_ip > max_address {
                    max_address = next_ip;
                }

                if instruction.mnemonic() == Mnemonic::Call
                    && let Some(target) = get_branch_target(&instruction)
                {
                    analysis.calls.push(FunctionCall {
                        address: ip,
                        target,
                    });
                }

                // Check for memory operands that could be data references
                if !matches!(instruction.mnemonic(), Mnemonic::Jmp | Mnemonic::Call) {
                    for i in 0..instruction.op_count() {
                        if instruction.op_kind(i) == OpKind::Memory {
                            // Check if it's RIP-relative (typical for data references)
                            // Also check for displacement-only addressing (absolute addresses)
                            // BUT exclude segment-relative addressing (GS, FS, etc)
                            if instruction.memory_base() == Register::RIP
                                || (instruction.memory_base() == Register::None
                                    && instruction.memory_index() == Register::None
                                    && instruction.memory_displacement64() != 0
                                    && instruction.segment_prefix() == Register::None)
                            {
                                let target_address = instruction.memory_displacement64();
                                let is_readonly =
                                    !mem.is_address_writable(target_address).unwrap_or(false);
                                analysis.data_refs.push(DataReference {
                                    address: ip,
                                    target: target_address,
                                    is_readonly,
                                    estimated_size: estimate_data_size_from_instruction(
                                        &instruction,
                                    ),
                                });
                            }
                        }
                    }
                }

                match instruction.flow_control() {
                    FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {}
                    FlowControl::UnconditionalBranch => {
                        block_intervals.insert(BlockBound::End(next_ip));
                        if let Some(target) = get_branch_target(&instruction) {
                            if target >= va && target < va + scan_size as u64 {
                                // In-window: tail-call vs internal-jump
                                // classification depends on FDE bounds (or, with
                                // none, on how far past `max_address` the target
                                // sits), so defer to the drain below where
                                // `max_address` has finished growing.
                                tailcall_queue.push_back((target, Some(ip)));
                            } else {
                                // Outside the (FDE-clamped) window: a tail call.
                                // Record the edge so the call graph stays
                                // connected.
                                analysis.calls.push(FunctionCall {
                                    address: ip,
                                    target,
                                });
                            }
                        }
                        break;
                    }
                    FlowControl::ConditionalBranch => {
                        // Follow both paths
                        block_intervals.insert(BlockBound::Start(next_ip));

                        if let Some(target) = get_branch_target(&instruction)
                            && target >= va
                            && target < va + scan_size as u64
                        {
                            // Internal jump - follow it
                            queue.push_back((target, Some(ip)));
                            block_intervals.insert(BlockBound::Start(target));
                        }
                    }
                    FlowControl::Return => {
                        // Return instruction - path ends here
                        // The next instruction (if any) starts a new block
                        if next_ip < va + scan_size as u64 {
                            block_intervals.insert(BlockBound::End(next_ip));
                        }
                        break;
                    }
                    FlowControl::IndirectBranch => {
                        // Indirect jump (like jmp rax or jmp [rax]). For PE32 we
                        // try to recognise the MSVC `jmp [idx*4 + table]` switch
                        // pattern, read the absolute table, and follow its
                        // targets so the switch arms become part of the function.
                        // Other arches / x86-64 keep the conservative behaviour
                        // (treat the indirect jump as an unfollowable block end).
                        if mem.is_pe()
                            && mem.bitness() == 32
                            && let Some((table, targets)) = detect_jump_table(&instruction, mem)
                        {
                            trace!(
                                target: "binfold::arch::size",
                                address = format!("0x{ip:x}"),
                                targets = targets.len(),
                                "Found PE32 jump table"
                            );
                            for target in targets {
                                if target >= va && target < va + scan_size as u64 {
                                    queue.push_back((target, Some(ip)));
                                    block_intervals.insert(BlockBound::Start(target));
                                }
                            }
                            analysis.jump_tables.push(table);
                        } else {
                            trace!(
                                target: "binfold::arch::size",
                                address = format!("0x{ip:x}"),
                                "Found indirect branch"
                            );
                        }
                        // The next instruction (if any) starts a new block
                        if next_ip < va + scan_size as u64 {
                            block_intervals.insert(BlockBound::End(next_ip));
                        }
                        break;
                    }
                    _ => {
                        trace!(
                            target: "binfold::arch::size",
                            flow_control = ?instruction.flow_control(),
                            address = format!("0x{:x}", ip),
                            "Unhandled flow control"
                        );
                        break;
                    }
                }
            }

            tailcall_queue.retain(|item| {
                let target = item.0;
                // With an FDE end, any in-window target is internal: the FDE
                // already bounds the function, so a forward `jmp` landing well
                // past the visited high-water mark (jump-table fall-through,
                // compiler-split block) is real internal code, not a tail call.
                // Without one, fall back to the `max_address + threshold`
                // distance heuristic, but still reject any target landing
                // exactly on a known function start - that is always a tail
                // call regardless of how close it sits (a neighbouring function
                // can begin only a few bytes after our `ret`).
                let is_internal = match fde_end {
                    Some(end) => target >= va && target < end,
                    None => {
                        target < max_address + tail_call_threshold
                            && !mem.is_known_function_start(target)
                    }
                };
                if is_internal {
                    block_intervals.insert(BlockBound::Start(target));
                    queue.push_back(*item);
                    false
                } else {
                    // Tail call. `item.1` is the address of the jmp instruction (threaded
                    // through the queue); fall back to the target if it's somehow absent.
                    analysis.calls.push(FunctionCall {
                        address: item.1.unwrap_or(target),
                        target,
                    });
                    true
                }
            });
        }

        let size = (max_address - va) as usize;
        if size == 0 {
            bail!("Could not determine function size")
        }
        analysis.size = size;

        {
            let mut start = None;
            for bound in &block_intervals {
                if let Some(addr) = start
                    && addr != bound.address()
                {
                    analysis.basic_blocks.insert(addr, bound.address());
                    start = None;
                }
                if let BlockBound::Start(a) = bound {
                    start = Some(*a);
                }
            }
            if let Some(start) = start
                && start != max_address
            {
                analysis.basic_blocks.insert(start, max_address);
            }
        }

        debug!(
            target: "binfold::arch::size",
            start = format!("0x{va:x}"),
            end = format!("0x{max_address:x}"),
            size = format!("0x{size:x}"),
            "Function size analysis complete"
        );

        Ok(analysis)
    }
}

fn estimate_data_size_from_instruction(instruction: &Instruction) -> Option<u32> {
    for i in 0..instruction.op_count() {
        if instruction.op_kind(i) == OpKind::Memory {
            let size = instruction.memory_size().size();
            if size == 0 {
                return None;
            } else {
                return Some(size as u32);
            }
        }
    }

    None
}

/// Recognise the MSVC PE32 switch dispatch `jmp [index*4 + table_base]`, read
/// the absolute jump table at `table_base`, and return its extent plus the
/// target addresses. Returns `None` when the instruction isn't this pattern or
/// the table doesn't validate. PE32-only; callers gate on bitness/format.
fn detect_jump_table(
    instruction: &Instruction,
    mem: &dyn MemoryView,
) -> Option<(JumpTable, Vec<u64>)> {
    if instruction.mnemonic() != Mnemonic::Jmp || instruction.op_count() == 0 {
        return None;
    }
    if instruction.op_kind(0) != OpKind::Memory {
        return None;
    }

    // Pattern: jmp [reg*4 + table_address] with an absolute 32-bit displacement.
    if instruction.memory_base() != Register::None
        || instruction.memory_index() == Register::None
        || instruction.memory_index_scale() != 4
        || instruction.memory_displacement64() == 0
    {
        return None;
    }

    let table_address = instruction.memory_displacement64();
    let targets = parse_jump_table(mem, table_address);
    if targets.is_empty() {
        return None;
    }

    let table = JumpTable {
        start: table_address,
        end: table_address + 4 * targets.len() as u64,
    };
    trace!(
        target: "binfold::arch::size",
        instruction = format!("0x{:x}", instruction.ip()),
        table = format!("0x{table_address:x}"),
        targets = targets.len(),
        "Parsed PE32 jump table"
    );
    Some((table, targets))
}

/// Read consecutive 4-byte absolute entries at `table_address`, stopping at the
/// first entry that isn't a plausible code pointer (zero, out of section, or
/// not a decodable instruction).
fn parse_jump_table(mem: &dyn MemoryView, table_address: u64) -> Vec<u64> {
    let mut targets = Vec::new();
    if !mem.is_address_in_section(table_address) {
        return targets;
    }

    for i in 0u64.. {
        let entry_address = table_address + i * 4;
        let target = match mem.read_at_va(entry_address, 4) {
            Ok(bytes) => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
            Err(_) => break,
        };

        // End of table: null or non-section entry.
        if target == 0 || !mem.is_address_in_section(target) {
            break;
        }

        // Sanity-check that the target decodes as an instruction; a run of data
        // that happens to look like an in-section pointer ends the table here.
        match mem.read_at_va(target, 16) {
            Ok(bytes) => {
                let mut decoder =
                    Decoder::with_ip(mem.bitness(), bytes, target, DecoderOptions::NONE);
                if decoder.decode().mnemonic() == Mnemonic::INVALID {
                    break;
                }
                targets.push(target);
            }
            Err(_) => break,
        }
    }

    targets
}
