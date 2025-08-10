use crate::pe_loader::{AnalysisCache, FunctionAnalysis, PeLoader};
use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
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
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub Uuid);
        impl $name {
            pub fn nil() -> Self {
                Self(Uuid::nil())
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

new_guid!(FunctionGuid);
new_guid!(BasicBlockGuid);
new_guid!(SymbolGuid);
new_guid!(ConstraintGuid);

impl FunctionGuid {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(Uuid::new_v5(&NAMESPACE_FUNCTION, bytes))
    }
}

impl BasicBlockGuid {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(Uuid::new_v5(&NAMESPACE_BASIC_BLOCK, bytes))
    }
}

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
    pub size: usize,
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone)]
pub struct Constraint {
    pub guid: ConstraintGuid,
    pub offset: Option<i64>,
}

pub fn compute_function_guid(
    pe: &PeLoader,
    cache: &AnalysisCache,
    address: u64,
) -> Result<FunctionGuid> {
    let func = cache.get(address, pe)?;
    debug!(size = format!("0x{:x}", func.size), "Function size");

    compute_warp_uuid(&func, pe)
}

pub fn compute_function_guid_with_contraints(
    pe: &PeLoader,
    cache: &AnalysisCache,
    address: u64,
) -> Result<Function> {
    let func = cache.get(address, pe)?;
    debug!(size = format!("0x{:x}", func.size), "Function size");

    let guid = compute_warp_uuid(&func, pe)?;

    // Generate constraints from calls
    let mut constraints: Vec<Constraint> = func
        .calls
        .iter()
        .map(|c| {
            compute_function_guid(pe, cache, c.target).map(|guid| Constraint {
                guid: ConstraintGuid::from_child_call(guid),
                offset: Some((c.address - func.entry_point) as i64),
            })
        })
        .collect::<Result<_>>()?;

    // Add data reference constraints
    for data_ref in &func.data_refs {
        if data_ref.is_readonly && data_ref.estimated_size.is_none() {
            // For read-only data with no specific size (strings), try to read and hash the content
            if let Some(data) = read_string_data(pe, data_ref.target) {
                constraints.push(Constraint {
                    guid: ConstraintGuid::from_data_const(&data),
                    offset: Some((data_ref.address - func.entry_point) as i64),
                });
            }
        }
    }

    Ok(Function {
        address: func.entry_point,
        size: func.size,
        guid,
        constraints,
    })
}

pub fn compute_warp_uuid(func: &FunctionAnalysis, pe: &PeLoader) -> Result<FunctionGuid> {
    debug!(blocks = func.basic_blocks.len(), "Identified basic blocks");

    let raw_bytes = pe.read_at_va(func.entry_point, func.size)?;
    let base = func.entry_point;

    // Create UUID for each basic block
    let mut block_uuids = Vec::new();
    for (&start_addr, &end_addr) in func.basic_blocks.iter() {
        // println!("{:x?}", (start_addr - base, end_addr - base, base));
        let block_bytes = &raw_bytes[(start_addr - base) as usize..(end_addr - base) as usize];
        let uuid = create_basic_block_guid(
            block_bytes,
            start_addr,
            base..(base + raw_bytes.len() as u64),
            pe,
        );
        block_uuids.push((start_addr, uuid));

        debug!(
            block_start = format!("0x{start_addr:x}"),
            block_end = format!("0x{end_addr:x}"),
            uuid = %uuid,
            "Block UUID computed"
        );
    }

    // Print disassembly for each basic block if requested
    if tracing::enabled!(target: "binfold::warp::blocks", tracing::Level::DEBUG) {
        for (&start_addr, &end_addr) in &func.basic_blocks {
            debug!(
                start = format!("0x{start_addr:x}"),
                end = format!("0x{end_addr:x}"),
                "Basic block"
            );

            // Disassemble the block
            let block_start_offset = (start_addr - base) as usize;
            let block_end_offset = (end_addr - base) as usize;
            let block_bytes = &raw_bytes[block_start_offset..block_end_offset];

            let mut decoder =
                Decoder::with_ip(pe.bitness(), block_bytes, start_addr, DecoderOptions::NONE);
            let mut output = String::new();

            while decoder.can_decode() {
                let instruction = decoder.decode();
                output.clear();
                trace!(
                    target: "binfold::warp::blocks",
                    addr = format!("0x{:x}", instruction.ip()),
                    instruction = %instruction,
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
        combined_bytes.extend_from_slice(uuid.0.as_bytes());
    }

    let function_uuid = FunctionGuid::from_bytes(&combined_bytes);

    debug!(
        target: "binfold::warp::guid",
        block_count = block_uuids.len(),
        function_uuid = %function_uuid,
        "Function UUID calculated"
    );

    Ok(function_uuid)
}

fn get_branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction.op_kind(0) {
        OpKind::NearBranch16 => Some(instruction.near_branch16() as u64),
        OpKind::NearBranch32 => Some(instruction.near_branch32() as u64),
        OpKind::NearBranch64 => Some(instruction.near_branch64()),
        _ => None,
    }
}

pub fn create_basic_block_guid(
    raw_bytes: &[u8],
    base: u64,
    function_bounds: Range<u64>,
    pe: &PeLoader,
) -> BasicBlockGuid {
    let mut bytes = Vec::new();

    let mut decoder = Decoder::new(pe.bitness(), raw_bytes, DecoderOptions::NONE);
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
        if is_relocatable_instruction(&instruction, function_bounds.clone()) {
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

    BasicBlockGuid::from_bytes(&bytes)
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

fn is_relocatable_instruction(instruction: &Instruction, function_bounds: Range<u64>) -> bool {
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
