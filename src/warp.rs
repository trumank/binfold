use crate::arch::BlockMasker;
use crate::binary::{AnalysisCache, Arch, Binary, FunctionAnalysis};
use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions};
use tracing::{debug, trace};

pub use crate::hash::{
    BasicBlockGuid, BasicBlockTag, ChildCallTag, ConstraintGuid, ConstraintTag, DataConstTag,
    DomainTag, FunctionGuid, FunctionTag, Guid, HashAlgo, ParentCallTag, SymbolChildCallTag,
    SymbolGuid, SymbolParentCallTag, SymbolTag, UuidV5,
};

#[derive(Debug, Clone)]
pub struct Function<H: HashAlgo> {
    pub guid: FunctionGuid<H>,
    pub address: u64,
    pub size: usize,
    pub constraints: Vec<Constraint<H>>,
}

impl<H: HashAlgo> Default for Function<H> {
    fn default() -> Self {
        Self {
            guid: FunctionGuid::default(),
            address: 0,
            size: 0,
            constraints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Constraint<H: HashAlgo> {
    pub guid: ConstraintGuid<H>,
    pub offset: Option<i64>,
}

pub fn compute_function_guid<H: HashAlgo>(
    bin: &Binary,
    cache: &AnalysisCache,
    address: u64,
) -> Result<FunctionGuid<H>> {
    let func = cache.get(address, bin)?;
    debug!(size = format!("0x{:x}", func.size), "Function size");

    compute_warp_uuid::<H>(&func, bin)
}

pub fn compute_function_guid_with_contraints<H: HashAlgo>(
    bin: &Binary,
    cache: &AnalysisCache,
    address: u64,
) -> Result<Function<H>> {
    let func = cache.get(address, bin)?;
    debug!(size = format!("0x{:x}", func.size), "Function size");

    let guid = compute_warp_uuid::<H>(&func, bin)?;

    // Generate constraints from calls
    // A direct call whose target lies outside any loaded segment (an import
    // thunk, a runtime-resolved stub, or a load-time trampoline table, common
    // in stripped/obfuscated Android `.so`s) cannot yield a child-call
    // constraint. Skip it rather than aborting the whole function: dropping the
    // single constraint is deterministic across DB-build and analysis, so
    // matching stays consistent.
    let mut constraints: Vec<Constraint<H>> = func
        .calls
        .iter()
        .filter_map(|c| {
            let guid = compute_function_guid::<H>(bin, cache, c.target).ok()?;
            Some(Constraint {
                guid: ConstraintGuid::<H>::from_child_call(guid),
                offset: Some((c.address - func.entry_point) as i64),
            })
        })
        .collect();

    // Add data reference constraints
    for data_ref in &func.data_refs {
        if data_ref.is_readonly && data_ref.estimated_size.is_none() {
            // For read-only data with no specific size (strings), try to read and hash the content
            if let Some(data) = read_string_data(bin, data_ref.target) {
                constraints.push(Constraint {
                    guid: ConstraintGuid::<H>::from_data_const(&data),
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

pub fn compute_warp_uuid<H: HashAlgo>(
    func: &FunctionAnalysis,
    bin: &Binary,
) -> Result<FunctionGuid<H>> {
    debug!(blocks = func.basic_blocks.len(), "Identified basic blocks");

    let raw_bytes = bin.read_at_va(func.entry_point, func.size)?;
    let base = func.entry_point;

    // Create UUID for each basic block
    let mut block_uuids = Vec::new();
    // One masker per function, iterating blocks in address order. Arm64's
    // masker threads ADRP register-taint across blocks so a page set up in the
    // prologue and consumed in a later block still gets its lo12 immediate
    // masked; the x86 masker is stateless.
    let mut masker: Box<dyn BlockMasker> = if matches!(bin.arch()?, Arch::Aarch64) {
        Box::new(crate::arch::arm64::Arm64Masker::default())
    } else {
        Box::new(crate::arch::x86::X86Masker::new(bin.bitness()))
    };
    for (&start_addr, &end_addr) in func.basic_blocks.iter() {
        // println!("{:x?}", (start_addr - base, end_addr - base, base));
        let block_bytes = &raw_bytes[(start_addr - base) as usize..(end_addr - base) as usize];
        let bytes = masker.mask(block_bytes, start_addr, base..base + raw_bytes.len() as u64);
        let uuid = BasicBlockGuid::<H>::from_bytes(&bytes);
        block_uuids.push((start_addr, uuid));

        debug!(
            block_start = format!("0x{start_addr:x}"),
            block_end = format!("0x{end_addr:x}"),
            uuid = %uuid,
            "Block UUID computed"
        );
    }

    // Print disassembly for each basic block if requested. The pretty-print
    // loop below decodes with iced-x86; skip on arm64 since iced would
    // disassemble A64 bytes as garbage x86.
    if tracing::enabled!(target: "binfold::warp::blocks", tracing::Level::DEBUG)
        && !matches!(bin.arch().unwrap_or(Arch::X86_64), Arch::Aarch64)
    {
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
                Decoder::with_ip(bin.bitness(), block_bytes, start_addr, DecoderOptions::NONE);
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
        combined_bytes.extend_from_slice(H::digest_bytes(&uuid.digest).as_ref());
    }

    let function_uuid = FunctionGuid::<H>::from_bytes(&combined_bytes);

    debug!(
        target: "binfold::warp::guid",
        block_count = block_uuids.len(),
        function_uuid = %function_uuid,
        "Function UUID calculated"
    );

    Ok(function_uuid)
}

/// Try to read string data from the given address
/// Returns the string bytes if it looks like a valid UTF-8 or UTF-16 string
pub fn read_string_data(bin: &Binary, address: u64) -> Option<Vec<u8>> {
    const MAX_STRING_LEN: usize = 4096;

    // Read first two bytes to determine string type
    let initial_bytes = bin.read_at_va(address, 2).ok()?;

    // Simple heuristic: if second byte is 0, assume UTF-16 LE
    if initial_bytes[1] == 0 {
        // Read UTF-16 string until double null bytes
        let mut result = Vec::new();
        let mut offset = 0;

        while offset < MAX_STRING_LEN {
            match bin.read_at_va(address + offset as u64, 2) {
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
            match bin.read_at_va(address + offset as u64, 1) {
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
