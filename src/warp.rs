use crate::pe_loader::PeLoader;
use anyhow::Result;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, Mnemonic, OpKind, Register,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;
use tracing::{debug, trace};
use uuid::{Uuid, uuid};

const NAMESPACE_FUNCTION: Uuid = uuid!("0192a179-61ac-7cef-88ed-012296e9492f");
const NAMESPACE_BASIC_BLOCK: Uuid = uuid!("0192a178-7a5f-7936-8653-3cbaa7d6afe7");
const NAMESPACE_SYMBOL: Uuid = uuid!("6d5ace5a-0050-4e71-815e-5536e9e61484");
const NAMESPACE_CHILD_CALL: Uuid = uuid!("7e3d0b40-56dd-4b77-a825-9c75b0b607c5");
const NAMESPACE_PARENT_CALL: Uuid = uuid!("dc0e3d9d-72ea-46df-81fc-ebe4295f0977");
const NAMESPACE_SYMBOL_CHILD_CALL: Uuid = uuid!("18811911-ca5d-4d97-a1c3-dd526ae818a5");
const NAMESPACE_SYMBOL_PARENT_CALL: Uuid = uuid!("e4b07ff0-e798-4427-b533-174aebda4858");
const NAMESPACE_DATA_CONST: Uuid = uuid!("db056d71-7d64-4660-a937-aeb6e8136af2");

macro_rules! new_guid {
    ($name:ident) => {
        #[derive(
            Debug,
            Default,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            serde::Deserialize,
            serde::Serialize,
        )]
        pub struct $name(pub Uuid);
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
        impl rusqlite::ToSql for $name {
            fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
                self.0.to_sql()
            }
        }
        impl rusqlite::types::FromSql for $name {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> rusqlite::types::FromSqlResult<Self> {
                rusqlite::types::FromSql::column_result(value).map(Self)
            }
        }
    };
}

new_guid!(FunctionGuid);
new_guid!(BasicBlockGuid);
new_guid!(SymbolGuid);
new_guid!(ConstraintGuid);

impl ConstraintGuid {
    /// constraint on call to target function
    pub fn from_child_call(target: FunctionGuid) -> Self {
        Self(Uuid::new_v5(&NAMESPACE_CHILD_CALL, target.0.as_bytes()))
    }
    /// constraint on target calling this function
    pub fn from_parent_call(target: FunctionGuid) -> Self {
        Self(Uuid::new_v5(&NAMESPACE_PARENT_CALL, target.0.as_bytes()))
    }
    /// constraint on call to target function
    pub fn from_symbol_child_call(target: SymbolGuid) -> Self {
        Self(Uuid::new_v5(
            &NAMESPACE_SYMBOL_CHILD_CALL,
            target.0.as_bytes(),
        ))
    }
    /// constraint on target calling this function
    pub fn from_symbol_parent_call(target: SymbolGuid) -> Self {
        Self(Uuid::new_v5(
            &NAMESPACE_SYMBOL_PARENT_CALL,
            target.0.as_bytes(),
        ))
    }
    /// constraint on reference to read-only data
    pub fn from_data_const(data: &[u8]) -> Self {
        Self(Uuid::new_v5(&NAMESPACE_DATA_CONST, data))
    }
}

impl SymbolGuid {
    pub fn from_symbol(symbol_name: impl AsRef<str>) -> SymbolGuid {
        Self(Uuid::new_v5(
            &NAMESPACE_SYMBOL,
            symbol_name.as_ref().as_bytes(),
        ))
    }
}

#[derive(Default, Debug, Clone)]
pub struct Function {
    pub guid: FunctionGuid,
    pub address: u64,
    pub constraints: Vec<Constraint>,
    pub calls: Vec<FunctionCall>,
    pub data_refs: Vec<DataReference>,
}

#[derive(Debug, Clone)]
pub struct Constraint {
    pub guid: ConstraintGuid,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct FunctionCall {
    /// function call target
    pub target: u64,
    /// offset from calling function entrypoint
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct DataReference {
    /// target address of data reference
    pub target: u64,
    /// offset from calling function entrypoint
    pub offset: u64,
    /// whether the reference is to read-only data
    pub is_readonly: bool,
    /// estimated size of the data being referenced (based on instruction)
    pub estimated_size: Option<u32>,
}

pub fn compute_warp_uuid_from_pe(pe: &PeLoader, address: u64) -> Result<FunctionGuid> {
    // Build CFG during size calculation
    let mut cfg = crate::pe_loader::ControlFlowGraph::default();
    let func_size = pe.find_function_size_with_cfg(address, Some(&mut cfg))?;

    debug!(
        target: "warp_testing::warp",
        size = format!("0x{func_size:x}"),
        "Function size"
    );

    let func_bytes = pe.read_at_va(address, func_size)?;

    Ok(compute_warp_uuid(func_bytes, address, None, None, &cfg, pe))
}

pub fn compute_function_guid_with_contraints(pe: &PeLoader, address: u64) -> Result<Function> {
    // Build CFG during size calculation
    let mut cfg = crate::pe_loader::ControlFlowGraph::default();
    let func_size = pe.find_function_size_with_cfg(address, Some(&mut cfg))?;

    debug!(
        target: "warp_testing::warp",
        size = format!("0x{func_size:x}"),
        "Function size"
    );

    let func_bytes = pe.read_at_va(address, func_size)?;

    let mut calls = vec![];
    let mut data_refs = vec![];
    let guid = compute_warp_uuid(
        func_bytes,
        address,
        Some(&mut calls),
        Some(&mut data_refs),
        &cfg,
        pe,
    );

    // Generate constraints from calls
    let mut constraints: Vec<Constraint> = calls
        .iter()
        .map(|c| {
            compute_warp_uuid_from_pe(pe, c.target).map(|guid| Constraint {
                guid: ConstraintGuid::from_child_call(guid),
                offset: Some(c.offset as i64),
            })
        })
        .collect::<Result<_>>()?;

    // Add data reference constraints
    for data_ref in &data_refs {
        if data_ref.is_readonly && data_ref.estimated_size.is_none() {
            // For read-only data with no specific size (strings), try to read and hash the content
            if let Some(data) = read_string_data(pe, data_ref.target) {
                constraints.push(Constraint {
                    guid: ConstraintGuid::from_data_const(&data),
                    offset: Some(data_ref.offset as i64),
                });
            }
        }
    }

    Ok(Function {
        address,
        guid,
        constraints,
        calls,
        data_refs,
    })
}

pub fn compute_warp_uuid(
    raw_bytes: &[u8],
    base: u64,
    mut calls: Option<&mut Vec<FunctionCall>>,
    mut data_refs: Option<&mut Vec<DataReference>>,
    cfg: &crate::pe_loader::ControlFlowGraph,
    pe: &PeLoader,
) -> FunctionGuid {
    // Disassemble and identify basic blocks
    let basic_blocks = identify_basic_blocks(raw_bytes, base, cfg);

    debug!(
        target: "warp_testing::warp",
        blocks = basic_blocks.len(),
        "Identified basic blocks"
    );

    // Create UUID for each basic block
    let mut block_uuids = Vec::new();
    for (&start_addr, &end_addr) in basic_blocks.iter() {
        // println!("{:x?}", (start_addr - base, end_addr - base, base));
        let block_bytes = &raw_bytes[(start_addr - base) as usize..(end_addr - base) as usize];
        let uuid = create_basic_block_guid(
            block_bytes,
            start_addr,
            base..(base + raw_bytes.len() as u64),
            calls.as_deref_mut(),
            data_refs.as_deref_mut(),
            pe,
        );
        block_uuids.push((start_addr, uuid));

        debug!(
            target: "warp_testing::warp::guid",
            block_start = format!("0x{start_addr:x}"),
            block_end = format!("0x{end_addr:x}"),
            uuid = %uuid,
            "Block UUID computed"
        );
    }

    // Print disassembly for each basic block if requested
    if tracing::enabled!(target: "warp_testing::warp::blocks", tracing::Level::DEBUG) {
        for (&start_addr, &end_addr) in &basic_blocks {
            debug!(
                target: "warp_testing::warp::blocks",
                start = format!("0x{start_addr:x}"),
                end = format!("0x{end_addr:x}"),
                "Basic block"
            );

            // Disassemble the block
            let block_start_offset = (start_addr - base) as usize;
            let block_end_offset = (end_addr - base) as usize;
            let block_bytes = &raw_bytes[block_start_offset..block_end_offset];

            let mut decoder = Decoder::with_ip(64, block_bytes, start_addr, DecoderOptions::NONE);
            let mut formatter = iced_x86::NasmFormatter::new();
            let mut output = String::new();

            while decoder.can_decode() {
                let instruction = decoder.decode();
                output.clear();
                formatter.format(&instruction, &mut output);
                trace!(
                    target: "warp_testing::warp::blocks",
                    addr = format!("0x{:x}", instruction.ip()),
                    instruction = %output,
                    "Instruction"
                );
            }
        }
    }

    // Combine block UUIDs to create function UUID
    // Note: Despite WARP spec saying "highest to lowest", Binary Ninja
    // actually combines them in low-to-high address order
    let mut combined_bytes = Vec::new();
    for (_, uuid) in block_uuids.iter() {
        combined_bytes.extend_from_slice(uuid.as_bytes());
    }

    let function_uuid = FunctionGuid(Uuid::new_v5(&NAMESPACE_FUNCTION, &combined_bytes));

    debug!(
        target: "warp_testing::warp::guid",
        block_count = block_uuids.len(),
        function_uuid = %function_uuid,
        "Function UUID calculated"
    );

    function_uuid
}

// Helper function to decode all instructions in a byte array
fn decode_instructions(raw_bytes: &[u8], base: u64) -> BTreeMap<u64, (Instruction, u64)> {
    let mut decoder = Decoder::with_ip(64, raw_bytes, base, DecoderOptions::NONE);
    let mut instructions = BTreeMap::new();

    while decoder.can_decode() {
        let start = decoder.ip();
        let instruction = decoder.decode();
        let end = decoder.ip();
        instructions.insert(start, (instruction, end));
    }

    instructions
}

pub fn identify_basic_blocks(
    raw_bytes: &[u8],
    base: u64,
    cfg: &crate::pe_loader::ControlFlowGraph,
) -> BTreeMap<u64, u64> {
    let instructions = decode_instructions(raw_bytes, base);

    debug!(
        target: "warp_testing::warp::blocks",
        instruction_count = instructions.len(),
        base = format!("0x{:x}", base),
        "Decoded instructions"
    );

    // Use the pre-built CFG from recursive descent
    debug!(
        target: "warp_testing::warp::blocks",
        block_starts = cfg.block_starts.len(),
        "Using CFG from recursive descent"
    );

    // The CFG from recursive descent only marks some block boundaries.
    // We need to enhance it with additional boundaries based on edge analysis
    let mut block_starts = cfg.block_starts.clone();

    // Build incoming/outgoing edge maps from the CFG
    let mut incoming_edges: HashMap<u64, HashSet<u64>> = HashMap::new();
    let mut outgoing_edges: HashMap<u64, HashSet<u64>> = HashMap::new();

    for (from, targets) in &cfg.edges {
        for &to in targets {
            incoming_edges.entry(to).or_default().insert(*from);
            outgoing_edges.entry(*from).or_default().insert(to);
        }
    }

    // Apply the same logic as linear sweep to find additional block boundaries
    for addr in cfg.visited_instructions.iter() {
        // Block start if multiple incoming edges
        if incoming_edges.get(addr).map(|s| s.len()).unwrap_or(0) > 1 {
            block_starts.insert(*addr);
        }

        // Block start if predecessor has multiple outgoing edges
        if let Some(predecessors) = incoming_edges.get(addr) {
            for &pred in predecessors {
                if outgoing_edges.get(&pred).map(|s| s.len()).unwrap_or(0) > 1 {
                    block_starts.insert(*addr);
                }
            }
        }
    }

    debug!(
        target: "warp_testing::warp::blocks",
        original_count = cfg.block_starts.len(),
        enhanced_count = block_starts.len(),
        "Enhanced CFG block starts"
    );

    // Filter block starts to only include those within our function bytes
    let end_addr = base + raw_bytes.len() as u64;
    block_starts.retain(|&addr| addr >= base && addr < end_addr);

    debug!(
        target: "warp_testing::warp::blocks",
        count = block_starts.len(),
        "Identified block start addresses"
    );

    // Build basic blocks for ALL code (not just reachable)
    // This is key - Binary Ninja identifies blocks even in unreachable code
    let mut basic_blocks = BTreeMap::new();
    let starts: Vec<u64> = block_starts.iter().cloned().collect();

    for start in starts {
        // Include ALL blocks, not just reachable ones
        // Binary Ninja includes unreachable blocks in its analysis

        let mut end = start;

        // Find the end of this basic block
        let mut current = start;
        while let Some((instruction, next)) = instructions.get(&current) {
            // Include current instruction in block
            end = *next;

            // Stop if this instruction doesn't fall through to the next
            if matches!(
                instruction.flow_control(),
                FlowControl::UnconditionalBranch | FlowControl::Return
            ) {
                break;
            }

            // Stop if the next instruction is the start of another block
            if block_starts.contains(next) && *next != start {
                break;
            }

            // Move to next instruction
            current = *next;

            // Stop if we've reached the end of instructions
            if !instructions.contains_key(&current) {
                break;
            }
        }

        if start != end {
            basic_blocks.insert(start, end);
        }
    }

    basic_blocks
}

fn get_branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction.op_kind(0) {
        OpKind::NearBranch16 => Some(instruction.near_branch16() as u64),
        OpKind::NearBranch32 => Some(instruction.near_branch32() as u64),
        OpKind::NearBranch64 => Some(instruction.near_branch64()),
        _ => None,
    }
}

fn create_basic_block_guid(
    raw_bytes: &[u8],
    base: u64,
    function_bounds: Range<u64>,
    calls: Option<&mut Vec<FunctionCall>>,
    data_refs: Option<&mut Vec<DataReference>>,
    pe: &PeLoader,
) -> Uuid {
    let instruction_bytes =
        get_instruction_bytes_for_guid(raw_bytes, base, function_bounds, calls, data_refs, pe);
    Uuid::new_v5(&NAMESPACE_BASIC_BLOCK, &instruction_bytes)
}

fn get_instruction_bytes_for_guid(
    raw_bytes: &[u8],
    base: u64,
    function_bounds: Range<u64>,
    mut calls: Option<&mut Vec<FunctionCall>>,
    mut data_refs: Option<&mut Vec<DataReference>>,
    pe: &PeLoader,
) -> Vec<u8> {
    use iced_x86::Formatter;

    let mut bytes = Vec::new();

    let mut decoder = Decoder::new(64, raw_bytes, DecoderOptions::NONE);
    decoder.set_ip(base);

    let mut formatter = iced_x86::NasmFormatter::new();
    let mut output = String::new();

    debug!(
        target: "warp_testing::warp::guid",
        "Starting instruction processing for GUID"
    );

    while decoder.can_decode() {
        let start = (decoder.ip() - base) as usize;
        let instruction = decoder.decode();
        let end = (decoder.ip() - base) as usize;
        let instr_bytes = &raw_bytes[start..end];

        output.clear();
        formatter.format(&instruction, &mut output);

        // NOPs handling is complex - Binary Ninja seems to include them
        // Only skip register-to-itself NOPs for hot-patching

        // Skip instructions that set a register to itself (if they're effectively NOPs)
        if is_register_to_itself_nop(&instruction) {
            trace!(
                target: "warp_testing::warp::guid",
                addr = format!("0x{:x}", instruction.ip()),
                instruction = %output,
                "Skipping register-to-itself NOP"
            );
            continue;
        }

        // Get instruction bytes, zeroing out relocatable instructions
        if is_relocatable_instruction(
            &instruction,
            function_bounds.clone(),
            calls.as_deref_mut(),
            data_refs.as_deref_mut(),
            pe,
        ) {
            // Zero out relocatable instructions
            bytes.extend(vec![0u8; instr_bytes.len()]);
            trace!(
                target: "warp_testing::warp::guid",
                addr = format!("0x{:x}", instruction.ip()),
                instruction = %output,
                bytes = format!("{:02x?}", instr_bytes),
                "Zeroing relocatable instruction"
            );
        } else {
            // Use actual instruction bytes
            bytes.extend_from_slice(instr_bytes);
            trace!(
                target: "warp_testing::warp::guid",
                addr = format!("0x{:x}", instruction.ip()),
                instruction = %output,
                bytes = format!("{:02x?}", instr_bytes),
                "Keeping instruction bytes"
            );
        }
    }

    bytes
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

fn is_relocatable_instruction(
    instruction: &Instruction,
    function_bounds: Range<u64>,
    calls: Option<&mut Vec<FunctionCall>>,
    mut data_refs: Option<&mut Vec<DataReference>>,
    pe: &PeLoader,
) -> bool {
    let offset = instruction.ip() - function_bounds.start;

    // Check for direct calls - but only forward calls are relocatable
    if instruction.mnemonic() == Mnemonic::Call && instruction.op_count() > 0 {
        match instruction.op_kind(0) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                // All direct calls are relocatable
                if let (Some(calls), Some(target)) = (calls, get_branch_target(instruction)) {
                    calls.push(FunctionCall { target, offset });
                }
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
                    if let Some(calls) = calls {
                        calls.push(FunctionCall { target, offset });
                    }
                    return true;
                }
            }
            _ => {}
        }
    }

    // Check for memory operands that could be data references
    if instruction.mnemonic() != Mnemonic::Call {
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

                    // Track this as a data reference if we have the data_refs vector
                    if let Some(data_refs) = data_refs.as_deref_mut() {
                        // Check if the target is writable
                        let is_readonly = !pe.is_address_writable(target_address).unwrap_or(false);
                        data_refs.push(DataReference {
                            target: target_address,
                            offset,
                            is_readonly,
                            estimated_size: estimate_data_size_from_instruction(instruction),
                        });
                    }
                }
            }
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

    false
}

/// Try to read string data from the given address
/// Returns the string bytes if it looks like a valid UTF-8 or UTF-16 string
pub fn read_string_data(pe: &PeLoader, address: u64) -> Option<Vec<u8>> {
    const MAX_STRING_LEN: usize = 4096;

    // Read first two bytes to determine string type
    let initial_bytes = pe.read_at_va(address, 2).ok()?;

    // Simple heuristic: if second byte is 0, assume UTF-16 LE
    if initial_bytes[1] == 0 {
        // Read UTF-16 string until double null bytes
        let mut result = Vec::new();
        let mut offset = 0;

        while offset < MAX_STRING_LEN {
            match pe.read_at_va(address + offset as u64, 2) {
                Ok(bytes) => {
                    if bytes[0] == 0 && bytes[1] == 0 {
                        break;
                    }
                    result.push(bytes[0]);
                    result.push(bytes[1]);
                    offset += 2;
                }
                Err(_) => break,
            }
        }

        // Validate it's actually UTF-16
        if result.len() > 4 {
            let u16_values: Vec<u16> = result
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();

            if String::from_utf16(&u16_values).is_ok() {
                return Some(result);
            }
        }
    } else {
        // Assume UTF-8, read until single null byte
        let mut result = Vec::new();
        let mut offset = 0;

        while offset < MAX_STRING_LEN {
            match pe.read_at_va(address + offset as u64, 1) {
                Ok(bytes) => {
                    if bytes[0] == 0 {
                        break;
                    }
                    result.push(bytes[0]);
                    offset += 1;
                }
                Err(_) => break,
            }
        }

        // Validate it's actually UTF-8
        if result.len() > 4 && std::str::from_utf8(&result).is_ok() {
            return Some(result);
        }
    }

    None
}

// >>> with open('/tmp/functions.json', 'w') as f:
//     json.dump([{"guid": str(binaryninja.warp.get_function_guid(f)), "start": f.start, "blocks": [{"start": b.start, "end": b.end, "guid": str(binaryninja.warp.get_basic_block_guid(b))} for b in sorted(f.basic_blocks)]} for f in bv.functions if len(f.basic_blocks) == 150], f)

#[cfg(test)]
mod test {
    use super::*;

    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Exe {
        path: String,
        functions: Vec<Function>,
    }

    #[derive(Debug, Deserialize)]
    struct Function {
        guid: FunctionGuid,
        start: u64,
        blocks: Vec<Block>,
    }

    #[derive(Debug, Deserialize)]
    struct Block {
        guid: Uuid,
        start: u64,
        end: u64,
    }

    #[test]
    fn test_json() {
        use std::io::Write;

        let f = std::io::BufReader::new(std::fs::File::open("functions.json").unwrap());
        let functions: Vec<Exe> = serde_json::from_reader(f).unwrap();

        let mut stats_file = std::fs::File::create("warp_test_stats.txt").unwrap();
        writeln!(stats_file, "WARP Function Analysis Statistics").unwrap();
        writeln!(stats_file, "==================================").unwrap();
        writeln!(
            stats_file,
            "Generated at: {:?}",
            std::time::SystemTime::now()
        )
        .unwrap();
        writeln!(stats_file).unwrap();

        let mut total_exact_matches = 0;
        let mut total_size_mismatches = 0;
        let mut total_blocks_analyzed = 0;
        let mut total_blocks_matched = 0;
        let mut total_functions = 0;

        // Collect detailed statistics
        let mut block_match_distribution: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut non_matching_functions = Vec::new();
        let mut perfect_block_no_guid = Vec::new();

        for exe in &functions {
            writeln!(stats_file, "\nExecutable: {}", exe.path).unwrap();
            writeln!(stats_file, "==========================================").unwrap();
            for (idx, function) in exe.functions.iter().enumerate() {
                writeln!(
                    stats_file,
                    "Function #{} at 0x{:x}",
                    idx + 1,
                    function.start
                )
                .unwrap();
                writeln!(stats_file, "  Expected GUID: {}", function.guid).unwrap();
                writeln!(stats_file, "  Expected blocks: {}", function.blocks.len()).unwrap();

                let Stats {
                    size_diff,
                    matching_blocks: blocks_matched,
                    found_blocks,
                    expected_blocks: blocks_total,
                    exact_match: guid_match,
                } = test_warp_function_from_binary(
                    &exe.path,
                    function.start,
                    function.guid,
                    function
                        .blocks
                        .iter()
                        .map(|b| (b.start, b.end, b.guid))
                        .collect(),
                );

                writeln!(stats_file, "  Size difference: {} bytes", size_diff).unwrap();
                writeln!(
                    stats_file,
                    "  Blocks matched (equal/found/expected): {blocks_matched}/{found_blocks}/{blocks_total} ({:.1}%)",
                    blocks_matched as f64 / blocks_total as f64 * 100.0
                )
                .unwrap();
                writeln!(
                    stats_file,
                    "  GUID match: {}",
                    if guid_match { "YES" } else { "NO" }
                )
                .unwrap();
                writeln!(stats_file).unwrap();

                if guid_match {
                    total_exact_matches += 1;
                }
                if size_diff != 0 {
                    total_size_mismatches += 1;
                }
                total_blocks_analyzed += blocks_total;
                total_blocks_matched += blocks_matched;
                total_functions += 1;

                let match_rate = blocks_matched as f64 / blocks_total as f64 * 100.0;
                let bucket = format!("{:.0}%", (match_rate / 10.0).floor() * 10.0);
                *block_match_distribution.entry(bucket).or_insert(0) += 1;

                if !guid_match {
                    non_matching_functions.push((
                        idx + 1,
                        function.start,
                        blocks_matched,
                        blocks_total,
                        match_rate,
                        exe.path.clone(),
                    ));
                    if blocks_matched == blocks_total && blocks_total == found_blocks {
                        perfect_block_no_guid.push((
                            idx + 1,
                            function.start,
                            function.guid.clone(),
                            exe.path.clone(),
                        ));
                    }
                }
            }
        }

        writeln!(stats_file, "Summary").unwrap();
        writeln!(stats_file, "=======").unwrap();
        writeln!(stats_file, "Total functions analyzed: {}", total_functions).unwrap();
        writeln!(
            stats_file,
            "Functions with exact GUID match: {}/{} ({:.1}%)",
            total_exact_matches,
            total_functions,
            total_exact_matches as f64 / total_functions as f64 * 100.0
        )
        .unwrap();
        writeln!(
            stats_file,
            "Functions with size mismatch: {}",
            total_size_mismatches
        )
        .unwrap();
        writeln!(
            stats_file,
            "Total basic blocks matched: {}/{} ({:.1}%)",
            total_blocks_matched,
            total_blocks_analyzed,
            total_blocks_matched as f64 / total_blocks_analyzed as f64 * 100.0
        )
        .unwrap();

        writeln!(stats_file, "\nBlock Match Distribution:").unwrap();
        writeln!(stats_file, "========================").unwrap();
        let mut buckets: Vec<_> = block_match_distribution.iter().collect();
        buckets.sort_by(|a, b| b.0.cmp(a.0));
        for (bucket, count) in buckets {
            writeln!(stats_file, "  {}: {} functions", bucket, count).unwrap();
        }

        writeln!(
            stats_file,
            "\nFunctions with 100% Block Match but Wrong GUID:"
        )
        .unwrap();
        writeln!(
            stats_file,
            "==============================================="
        )
        .unwrap();
        writeln!(stats_file, "Count: {}", perfect_block_no_guid.len()).unwrap();
        for (idx, addr, guid, exe_path) in perfect_block_no_guid.iter().take(10) {
            writeln!(
                stats_file,
                "  Function #{} at 0x{:x} (expected: {})",
                idx, addr, guid
            )
            .unwrap();
            writeln!(stats_file, "    in: {}", exe_path).unwrap();
        }
        if perfect_block_no_guid.len() > 10 {
            writeln!(
                stats_file,
                "  ... and {} more",
                perfect_block_no_guid.len() - 10
            )
            .unwrap();
        }

        writeln!(
            stats_file,
            "\nAll Non-Matching Functions by Block Match Rate:"
        )
        .unwrap();
        writeln!(stats_file, "==============================================").unwrap();
        non_matching_functions.sort_by(|a, b| b.4.partial_cmp(&a.4).unwrap());
        for (idx, addr, matched, total, rate, exe_path) in non_matching_functions.iter().take(20) {
            writeln!(
                stats_file,
                "  Function #{} at 0x{:x}: {}/{} blocks ({:.1}%)",
                idx, addr, matched, total, rate
            )
            .unwrap();
            writeln!(stats_file, "    in: {}", exe_path).unwrap();
        }
        if non_matching_functions.len() > 20 {
            writeln!(
                stats_file,
                "  ... and {} more",
                non_matching_functions.len() - 20
            )
            .unwrap();
        }
    }

    struct Stats {
        size_diff: i64,
        matching_blocks: usize,
        found_blocks: usize,
        expected_blocks: usize,
        exact_match: bool,
    }

    // Implementation of test WARP function from binary
    fn test_warp_function_from_binary(
        exe_path: impl AsRef<std::path::Path>,
        function_address: u64,
        expected_function_guid: FunctionGuid,
        expected_blocks: Vec<(u64, u64, Uuid)>,
    ) -> Stats {
        // Load main.exe from root directory
        let pe = PeLoader::load(exe_path).expect("Failed to load main.exe");

        // Use the heuristic to find function size
        let mut cfg = crate::pe_loader::ControlFlowGraph::default();
        let function_size = pe
            .find_function_size_with_cfg(function_address, Some(&mut cfg))
            .expect("Failed to determine function size");

        // Calculate expected size from the blocks
        let expected_size = if expected_blocks.is_empty() {
            0
        } else {
            let last_block = expected_blocks
                .iter()
                .max_by_key(|(_, end, _)| end)
                .unwrap();
            (last_block.1 - function_address) as usize
        };

        println!(
            "Function at 0x{:x}: detected size = 0x{:x}, expected size = 0x{:x} (diff = {})",
            function_address,
            function_size,
            expected_size,
            function_size as i64 - expected_size as i64
        );

        // Read the function bytes
        let function_bytes = pe
            .read_at_va(function_address, function_size)
            .expect("Failed to read function bytes");

        // Compute basic blocks using CFG from recursive descent
        // First get function size and build CFG
        let mut cfg = crate::pe_loader::ControlFlowGraph::default();
        let _size = pe
            .find_function_size_with_cfg(function_address, Some(&mut cfg))
            .expect("Failed to determine function size");

        let blocks = identify_basic_blocks(function_bytes, function_address, &cfg);

        println!("\nComparing basic blocks:");
        println!(
            "Start       | End         | Our GUID                             | Expected GUID                        | Match"
        );
        println!(
            "------------|-------------|--------------------------------------|--------------------------------------|-------"
        );

        let mut matching_blocks = 0;
        let mut mismatched_blocks = Vec::new();
        for &(start, end, expected_guid) in &expected_blocks {
            let our_end = blocks.get(&start);
            let our_guid = if let Some(&actual_end) = our_end {
                let block_bytes = &function_bytes
                    [(start - function_address) as usize..(actual_end - function_address) as usize];
                Some(create_basic_block_guid(
                    block_bytes,
                    start,
                    function_address..(function_address + function_size as u64),
                    None,
                    None,
                    &pe,
                ))
            } else {
                None
            };

            let guid_match = our_guid == Some(expected_guid);
            if guid_match {
                matching_blocks += 1;
            } else if our_end.is_some() {
                mismatched_blocks.push((start, end, *our_end.unwrap()));
            }

            println!(
                "0x{:08x} | 0x{:08x} | {} | {} | {}",
                start,
                end,
                our_guid
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "BLOCK_NOT_FOUND".to_string()),
                expected_guid,
                if guid_match { "YES" } else { "NO" }
            );
        }

        // Compute WARP UUID
        let warp_uuid = compute_warp_uuid(function_bytes, function_address, None, None, &cfg, &pe);
        println!("\nWARP UUID: {}", warp_uuid);
        println!("Expected:  {}", expected_function_guid);

        let exact_match = warp_uuid == expected_function_guid;
        let block_match_rate = matching_blocks as f64 / expected_blocks.len() as f64;

        println!("\nResults:");
        println!(
            "- Basic blocks: {}/{} match ({:.1}%)",
            matching_blocks,
            expected_blocks.len(),
            block_match_rate * 100.0
        );
        println!(
            "- WARP UUID: {}",
            if exact_match {
                "EXACT MATCH"
            } else {
                "MISMATCH"
            }
        );

        if !mismatched_blocks.is_empty() && exact_match {
            println!(
                "\nNote: Function UUID matches despite {} block mismatches:",
                mismatched_blocks.len()
            );
            for (start, expected_end, actual_end) in mismatched_blocks.iter().take(5) {
                println!(
                    "  Block 0x{:x}: expected end 0x{:x}, actual end 0x{:x} (diff: {})",
                    start,
                    expected_end,
                    actual_end,
                    *actual_end as i64 - *expected_end as i64
                );
            }
        }

        // Show a few basic blocks for debugging
        // if !exact_match || block_match_rate < 1.0 {
        //     println!("\nFirst 3 basic blocks:");
        //     let block_vec: Vec<_> = blocks.iter().take(3).collect();
        //     for &(&start_addr, &end_addr) in &block_vec {
        //         println!("\nBasic block: 0x{start_addr:x} - 0x{end_addr:x}");
        //         println!("----------------------------------------");

        //         let block_start_offset = (start_addr - function_address) as usize;
        //         let block_end_offset = (end_addr - function_address) as usize;

        //         if block_end_offset <= function_bytes.len() {
        //             let block_bytes = &function_bytes[block_start_offset..block_end_offset];

        //             let mut decoder =
        //                 Decoder::with_ip(64, block_bytes, start_addr, DecoderOptions::NONE);
        //             let mut formatter = iced_x86::NasmFormatter::new();
        //             let mut output = String::new();

        //             while decoder.can_decode() {
        //                 let instruction = decoder.decode();
        //                 output.clear();
        //                 formatter.format(&instruction, &mut output);
        //                 println!("  0x{:x}: {}", instruction.ip(), output);
        //             }
        //         }
        //     }
        // }

        // Assertions for test validation
        assert!(function_size > 0, "Function size should be greater than 0");
        assert!(blocks.len() > 0, "Should have at least one basic block");

        // Return statistics: (size_diff, blocks_matched, blocks_total, guid_match)
        let size_diff = function_size as i64 - expected_size as i64;
        Stats {
            size_diff,
            matching_blocks,
            found_blocks: blocks.len(),
            expected_blocks: expected_blocks.len(),
            exact_match,
        }
    }
}
