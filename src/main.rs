use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, Mnemonic, OpKind, Register,
};
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

const FUNCTION_NAMESPACE: &str = "0192a179-61ac-7cef-88ed-012296e9492f";
const BASIC_BLOCK_NAMESPACE: &str = "0192a178-7a5f-7936-8653-3cbaa7d6afe7";

const TEST_FUNCTION_BYTES: &[u8] = &[
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xec, 0x30, 0xb9,
    0x01, 0x00, 0x00, 0x00, 0xe8, 0xb8, 0xfb, 0xff, 0xff, 0x84, 0xc0, 0x0f, 0x84, 0x36, 0x01, 0x00,
    0x00, 0x40, 0x32, 0xf6, 0x40, 0x88, 0x74, 0x24, 0x20, 0xe8, 0x85, 0xfb, 0xff, 0xff, 0x8a, 0xd8,
    0x8b, 0x0d, 0x9e, 0x6b, 0x00, 0x00, 0x83, 0xf9, 0x01, 0x0f, 0x84, 0x23, 0x01, 0x00, 0x00, 0x85,
    0xc9, 0x75, 0x4a, 0xc7, 0x05, 0x87, 0x6b, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x15,
    0x20, 0x50, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0xe9, 0x4c, 0x00, 0x00, 0xe8, 0xac, 0x12, 0x00, 0x00,
    0x85, 0xc0, 0x74, 0x0a, 0xb8, 0xff, 0x00, 0x00, 0x00, 0xe9, 0xd9, 0x00, 0x00, 0x00, 0x48, 0x8d,
    0x15, 0xbf, 0x4b, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x98, 0x49, 0x00, 0x00, 0xe8, 0x85, 0x12, 0x00,
    0x00, 0xc7, 0x05, 0x49, 0x6b, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xeb, 0x08, 0x40, 0xb6, 0x01,
    0x40, 0x88, 0x74, 0x24, 0x20, 0x8a, 0xcb, 0xe8, 0x03, 0xfb, 0xff, 0xff, 0xe8, 0xc2, 0xfa, 0xff,
    0xff, 0x48, 0x8b, 0xd8, 0x48, 0x83, 0x38, 0x00, 0x74, 0x1e, 0x48, 0x8b, 0xc8, 0xe8, 0x0c, 0xfa,
    0xff, 0xff, 0x84, 0xc0, 0x74, 0x12, 0x45, 0x33, 0xc0, 0x41, 0x8d, 0x50, 0x02, 0x33, 0xc9, 0x48,
    0x8b, 0x03, 0xff, 0x15, 0x6c, 0x99, 0x00, 0x00, 0xe8, 0xaf, 0xfa, 0xff, 0xff, 0x48, 0x8b, 0xd8,
    0x48, 0x83, 0x38, 0x00, 0x74, 0x14, 0x48, 0x8b, 0xc8, 0xe8, 0xe0, 0xf9, 0xff, 0xff, 0x84, 0xc0,
    0x74, 0x08, 0x48, 0x8b, 0x0b, 0xe8, 0x52, 0x12, 0x00, 0x00, 0xe8, 0x11, 0x12, 0x00, 0x00, 0x48,
    0x8b, 0xf8, 0xe8, 0x33, 0x12, 0x00, 0x00, 0x48, 0x8b, 0x18, 0xe8, 0x25, 0x12, 0x00, 0x00, 0x4c,
    0x8b, 0xc7, 0x48, 0x8b, 0xd3, 0x8b, 0x08, 0xe8, 0x2f, 0xfa, 0xff, 0xff, 0x8b, 0xd8, 0xe8, 0x32,
    0xfa, 0xff, 0xff, 0x84, 0xc0, 0x74, 0x55, 0x40, 0x84, 0xf6, 0x75, 0x05, 0xe8, 0x0f, 0x12, 0x00,
    0x00, 0x33, 0xd2, 0xb1, 0x01, 0xe8, 0x8a, 0xf9, 0xff, 0xff, 0x8b, 0xc3, 0xeb, 0x19, 0x8b, 0xd8,
    0xe8, 0x10, 0xfa, 0xff, 0xff, 0x84, 0xc0, 0x74, 0x3b, 0x80, 0x7c, 0x24, 0x20, 0x00, 0x75, 0x05,
    0xe8, 0xf1, 0x11, 0x00, 0x00, 0x8b, 0xc3, 0x48, 0x8b, 0x5c, 0x24, 0x40, 0x48, 0x8b, 0x74, 0x24,
    0x48, 0x48, 0x83, 0xc4, 0x30, 0x5f, 0xc3, 0xb9, 0x07, 0x00, 0x00, 0x00, 0xe8, 0x48, 0xfa, 0xff,
    0xff, 0x90, 0xb9, 0x07, 0x00, 0x00, 0x00, 0xe8, 0x3d, 0xfa, 0xff, 0xff, 0x8b, 0xcb, 0xe8, 0x9f,
    0x11, 0x00, 0x00,
];

fn main() {
    // Example x86_64 function bytes
    let function_bytes = vec![
        0x55, // push rbp
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0x48, 0x83, 0xec, 0x10, // sub rsp, 0x10
        0x89, 0x7d, 0xfc, // mov [rbp-4], edi
        0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
        0x83, 0xc0, 0x01, // add eax, 1
        0xc9, // leave
        0xc3, // ret
    ];

    let warp_uuid = compute_warp_uuid(&function_bytes, 0x1000);
    println!("WARP UUID: {}", warp_uuid);
}

fn compute_warp_uuid(raw_bytes: &[u8], base: u64) -> String {
    // Disassemble and identify basic blocks
    let basic_blocks = identify_basic_blocks(raw_bytes, base);

    // Create UUID for each basic block
    let mut block_uuids = Vec::new();
    for (&start_addr, &end_addr) in basic_blocks.iter() {
        let uuid = create_basic_block_guid(
            &raw_bytes[(start_addr - base) as usize..(end_addr - base) as usize],
            start_addr,
        );
        block_uuids.push((start_addr, uuid));
    }

    // Print disassembly for each basic block
    for (&start_addr, &end_addr) in &basic_blocks {
        println!("\nBasic block: 0x{start_addr:x} - 0x{end_addr:x}");
        println!("----------------------------------------");

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
            println!("  0x{:x}: {}", instruction.ip(), output);
        }
    }
    // Sort by address (highest to lowest)
    for (start_addr, uuid) in block_uuids.iter() {
        println!("0x{start_addr:x}: {uuid}");
    }

    // Combine block UUIDs to create function UUID
    let namespace = uuid::Uuid::parse_str(FUNCTION_NAMESPACE).unwrap();
    let mut combined_bytes = Vec::new();
    for (_, uuid) in block_uuids.iter().rev() {
        combined_bytes.extend_from_slice(uuid.as_bytes());
    }

    create_uuid_v5(&namespace, &combined_bytes).to_string()
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

// Helper function to build control flow graph
fn build_control_flow_graph(
    instructions: &BTreeMap<u64, (Instruction, u64)>,
    base: u64,
) -> (
    HashMap<u64, HashSet<u64>>,
    HashMap<u64, HashSet<u64>>,
    HashSet<u64>,
) {
    let mut incoming_edges: HashMap<u64, HashSet<u64>> = HashMap::new();
    let mut outgoing_edges: HashMap<u64, HashSet<u64>> = HashMap::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(base);

    while let Some(addr) = queue.pop_front() {
        if visited.contains(&addr) {
            continue;
        }
        visited.insert(addr);

        if let Some((instruction, next_addr)) = instructions.get(&addr) {
            match instruction.flow_control() {
                FlowControl::Next | FlowControl::Call => {
                    // Regular instruction or call - edge to next
                    outgoing_edges.entry(addr).or_default().insert(*next_addr);
                    incoming_edges.entry(*next_addr).or_default().insert(addr);
                    queue.push_back(*next_addr);
                }
                FlowControl::UnconditionalBranch => {
                    // Unconditional jump - edge to target only
                    if let Some(target) = get_branch_target(instruction) {
                        outgoing_edges.entry(addr).or_default().insert(target);
                        incoming_edges.entry(target).or_default().insert(addr);
                        queue.push_back(target);
                    }
                }
                FlowControl::ConditionalBranch => {
                    // Conditional jump - edges to both next and target
                    outgoing_edges.entry(addr).or_default().insert(*next_addr);
                    incoming_edges.entry(*next_addr).or_default().insert(addr);
                    queue.push_back(*next_addr);

                    if let Some(target) = get_branch_target(instruction) {
                        outgoing_edges.entry(addr).or_default().insert(target);
                        incoming_edges.entry(target).or_default().insert(addr);
                        queue.push_back(target);
                    }
                }
                FlowControl::Return => {
                    // Return - no outgoing edges
                }
                _ => {}
            }
        }
    }

    (incoming_edges, outgoing_edges, visited)
}

// Helper function to identify block boundaries
fn identify_block_boundaries(
    instructions: &BTreeMap<u64, (Instruction, u64)>,
    incoming_edges: &HashMap<u64, HashSet<u64>>,
    outgoing_edges: &HashMap<u64, HashSet<u64>>,
    base: u64,
) -> BTreeSet<u64> {
    let mut block_starts = BTreeSet::new();
    block_starts.insert(base); // Entry point is always a block start

    for (&addr, _) in instructions {
        // Block start if multiple incoming edges
        if incoming_edges.get(&addr).map(|s| s.len()).unwrap_or(0) > 1 {
            block_starts.insert(addr);
        }

        // Block start if predecessor has multiple outgoing edges
        if let Some(predecessors) = incoming_edges.get(&addr) {
            for &pred in predecessors {
                if outgoing_edges.get(&pred).map(|s| s.len()).unwrap_or(0) > 1 {
                    block_starts.insert(addr);
                }
            }
        }
    }

    // Block starts after returns and unconditional jumps
    let mut prev_instruction: Option<&Instruction> = None;
    for (&addr, (instruction, _)) in instructions {
        if let Some(prev) = prev_instruction {
            if matches!(
                prev.flow_control(),
                FlowControl::UnconditionalBranch | FlowControl::Return
            ) {
                block_starts.insert(addr);
            }
        }
        prev_instruction = Some(instruction);
    }

    block_starts
}

fn identify_basic_blocks(raw_bytes: &[u8], base: u64) -> BTreeMap<u64, u64> {
    let instructions = decode_instructions(raw_bytes, base);

    // Build control flow graph edges and find reachable instructions
    let (incoming_edges, outgoing_edges, visited) = build_control_flow_graph(&instructions, base);

    // Identify basic block boundaries
    let block_starts =
        identify_block_boundaries(&instructions, &incoming_edges, &outgoing_edges, base);

    // Build basic blocks (only for reachable code)
    let mut basic_blocks = BTreeMap::new();
    let starts: Vec<u64> = block_starts.iter().cloned().collect();

    for i in 0..starts.len() {
        let start = starts[i];

        // Skip if this block is not reachable
        if !visited.contains(&start) {
            continue;
        }

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

        basic_blocks.insert(start, end);
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

fn create_basic_block_guid(raw_bytes: &[u8], base: u64) -> uuid::Uuid {
    let namespace = uuid::Uuid::parse_str(BASIC_BLOCK_NAMESPACE).unwrap();
    let instruction_bytes = get_instruction_bytes_for_guid(raw_bytes, base);
    create_uuid_v5(&namespace, &instruction_bytes)
}

fn get_instruction_bytes_for_guid(raw_bytes: &[u8], base: u64) -> Vec<u8> {
    let mut bytes = Vec::new();

    let mut decoder = Decoder::new(64, raw_bytes, DecoderOptions::NONE);
    decoder.set_ip(base);

    while decoder.can_decode() {
        let start = (decoder.ip() - base) as usize;
        let instruction = decoder.decode();
        let end = (decoder.ip() - base) as usize;
        let instr_bytes = &raw_bytes[start..end];

        // Skip NOPs
        if instruction.mnemonic() == Mnemonic::Nop {
            continue;
        }

        // Skip instructions that set a register to itself (if they're effectively NOPs)
        if is_register_to_itself_nop(&instruction) {
            continue;
        }

        // Get instruction bytes, zeroing out relocatable instructions
        if is_relocatable_instruction(&instruction) {
            // Zero out relocatable instructions
            bytes.extend(vec![0u8; instr_bytes.len()]);
        } else {
            // Use actual instruction bytes
            bytes.extend_from_slice(&instr_bytes);
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

fn is_relocatable_instruction(instruction: &Instruction) -> bool {
    // Check for direct calls/jumps
    if matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Jmp) {
        if instruction.op_count() > 0
            && matches!(
                instruction.op_kind(0),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        {
            return true;
        }
    }

    // Check for instructions with immediate operands that could be addresses
    for i in 0..instruction.op_count() {
        if matches!(instruction.op_kind(i), OpKind::Immediate64 | OpKind::Memory) {
            // Check if this is likely an address operand
            if instruction.memory_base() != Register::None
                || instruction.memory_index() != Register::None
            {
                continue; // This is a register-relative address, not absolute
            }

            // If it's a direct memory reference, it's relocatable
            if instruction.op_kind(i) == OpKind::Memory {
                return true;
            }
        }
    }

    false
}

fn create_uuid_v5(namespace: &uuid::Uuid, data: &[u8]) -> uuid::Uuid {
    let mut hasher = Sha1::new();
    hasher.update(namespace.as_bytes());
    hasher.update(data);
    let hash = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);

    // Set version (5) and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    uuid::Uuid::from_bytes(bytes)
}

fn print_disassembly_with_edges(raw_bytes: &[u8], base: u64) {
    // Decode all instructions
    let instructions = decode_instructions(raw_bytes, base);

    // Build control flow graph edges (we don't need visited for display)
    let (incoming_edges, outgoing_edges, _) = build_control_flow_graph(&instructions, base);

    // Identify block boundaries
    let block_starts =
        identify_block_boundaries(&instructions, &incoming_edges, &outgoing_edges, base);

    // Print disassembly with edge information - LINEAR SWEEP
    let mut formatter = iced_x86::NasmFormatter::new();
    let mut output = String::new();

    println!("Address      | In  | Out | Instruction");
    println!("-------------|-----|-----|-------------");

    // Do a fresh linear sweep to catch everything
    let mut decoder = Decoder::with_ip(64, raw_bytes, base, DecoderOptions::NONE);

    while decoder.can_decode() {
        let addr = decoder.ip();

        // Print block boundary if needed
        if block_starts.contains(&addr) && addr != base {
            println!("-------------|-----|-----|------------- BLOCK BOUNDARY");
        }

        let instruction = decoder.decode();

        let in_edges = incoming_edges.get(&addr).map(|s| s.len()).unwrap_or(0);
        let out_edges = outgoing_edges.get(&addr).map(|s| s.len()).unwrap_or(0);

        output.clear();
        formatter.format(&instruction, &mut output);

        println!(
            "0x{:08x}  | {:3} | {:3} | {}",
            addr, in_edges, out_edges, output
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_big() {
        let base = 0x1400015ec;
        
        // Binary Ninja basic block GUIDs
        let expected_guids = vec![
            (0x1400015ec, 0x14000160d, "4cd8b165-f08e-59b6-bcb5-bcdf6cbed1df"),
            (0x14000160d, 0x14000162b, "1017b146-0888-599c-8e3e-e5901322c61c"),
            (0x14000162b, 0x14000162f, "030bf918-6106-5003-a82f-14f803b68de7"),
            (0x14000162f, 0x140001650, "8c6757ca-bb64-5354-aec9-d43052d0f43c"),
            (0x140001650, 0x14000165a, "f74ea2f7-3337-501c-a587-44cc19fe3926"),
            (0x14000165a, 0x140001679, "48c37997-7c61-590b-b5be-db22b8234722"),
            (0x140001679, 0x140001681, "959f5dee-e81b-5648-9da1-49cfbfda6ef1"),
            (0x140001681, 0x140001696, "b4848139-e544-555d-896a-c1cbcdcd1aef"),
            (0x140001696, 0x1400016a2, "b0dd7350-27ac-5e56-9ad4-aefe4c0bc3d2"),
            (0x1400016a2, 0x1400016b4, "6952f10c-d255-5a10-b605-2e772ab077b5"),
            (0x1400016b4, 0x1400016c2, "fda8b2d0-f5c5-5a18-8a9b-d7f3a1d32bd4"),
            (0x1400016c2, 0x1400016ce, "3b1a220f-21aa-5c1a-84dd-15478ddcd8ed"),
            (0x1400016ce, 0x1400016d6, "28b92727-1675-5ab4-8aa8-efdf10503cb1"),
            (0x1400016d6, 0x140001703, "43116bd4-d437-5c33-b334-9a20e8d2593b"),
            (0x140001703, 0x140001708, "64d222ab-fd59-5dae-917a-8acf93a623b1"),
            (0x140001708, 0x14000170d, "276080dd-41b1-52fa-b907-b6e17528147b"),
            (0x14000170d, 0x14000171a, "781b3161-a5f6-5246-8248-202713e7b1b7"),
            (0x140001733, 0x140001743, "10cc16f6-0eed-5e6a-8b56-7e35c6e7d33f"),
            (0x140001743, 0x14000174e, "3bd8e78b-1091-5f05-965d-b1093f29c6fa"),
            (0x14000174e, 0x140001758, "8e1db6ea-2719-547c-b067-d7657d21c74c"),
            (0x140001758, 0x14000175f, "5cf3a71c-168c-55b3-baa0-d0d8f3ae3a89"),
        ];
        
        // Compute our blocks and GUIDs
        let blocks = identify_basic_blocks(&TEST_FUNCTION_BYTES, base);
        let mut our_guids = Vec::new();
        
        for (&start_addr, &end_addr) in blocks.iter() {
            let uuid = create_basic_block_guid(
                &TEST_FUNCTION_BYTES[(start_addr - base) as usize..(end_addr - base) as usize],
                start_addr,
            );
            our_guids.push((start_addr, end_addr, uuid));
        }
        
        // Compare blocks and GUIDs
        println!("\nComparing with Binary Ninja:");
        println!("Start       | End         | Our GUID                             | BN GUID                              | Match");
        println!("------------|-------------|--------------------------------------|--------------------------------------|-------");
        
        for &(bn_start, bn_end, bn_guid) in &expected_guids {
            let our_block = blocks.get(&bn_start);
            let our_guid = our_guids.iter()
                .find(|(start, _, _)| *start == bn_start)
                .map(|(_, _, guid)| guid.to_string());
                
            let block_match = our_block == Some(&bn_end);
            let guid_match = our_guid.as_deref() == Some(bn_guid);
            
            println!(
                "0x{:08x} | 0x{:08x} | {} | {} | {}",
                bn_start,
                bn_end,
                our_guid.as_deref().unwrap_or("NOT FOUND"),
                bn_guid,
                if block_match && guid_match { "YES" } else if block_match { "BLOCK" } else { "NO" }
            );
        }
        
        // Compute WARP UUID
        let warp_uuid = compute_warp_uuid(TEST_FUNCTION_BYTES, base);
        println!("\nWARP UUID: {}", warp_uuid);
    }

    #[test]
    fn test_small() {
        let bytes = [
            0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x0d, 0x75, 0x57, 0x00, 0x00, 0xe8, 0x97, 0xfc,
            0xff, 0xff, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ];
        let warp_uuid = compute_warp_uuid(&bytes, 0x140001430);
        println!("WARP UUID: {}", warp_uuid);
    }

    #[test]
    fn test_disassembly() {
        println!("\nFull disassembly with edge information:");
        print_disassembly_with_edges(TEST_FUNCTION_BYTES, 0x1400015ec);
    }

    #[test]
    fn test_binary_ninja_blocks() {
        let base = 0x1400015ec;
        let blocks = identify_basic_blocks(&TEST_FUNCTION_BYTES, base);

        // Expected blocks from Binary Ninja
        let expected_blocks = vec![
            (0x1400015ec, 0x14000160d),
            (0x14000160d, 0x14000162b),
            (0x14000162b, 0x14000162f),
            (0x14000162f, 0x140001650),
            (0x140001650, 0x14000165a),
            (0x14000165a, 0x140001679),
            (0x140001679, 0x140001681),
            (0x140001681, 0x140001696),
            (0x140001696, 0x1400016a2),
            (0x1400016a2, 0x1400016b4),
            (0x1400016b4, 0x1400016c2),
            (0x1400016c2, 0x1400016ce),
            (0x1400016ce, 0x1400016d6),
            (0x1400016d6, 0x140001703),
            (0x140001703, 0x140001708),
            (0x140001708, 0x14000170d),
            (0x14000170d, 0x14000171a),
            (0x140001733, 0x140001743),
            (0x140001743, 0x14000174e),
            (0x14000174e, 0x140001758),
            (0x140001758, 0x14000175f),
        ];

        // Compare blocks
        println!("Our blocks vs Binary Ninja blocks:");
        for &(start, end) in &expected_blocks {
            let our_end = blocks.get(&start);
            println!(
                "0x{:x} - 0x{:x} | BN: 0x{:x} - 0x{:x} | Match: {}",
                start,
                our_end.unwrap_or(&0),
                start,
                end,
                our_end == Some(&end)
            );
        }

        // Check if we have blocks that BN doesn't
        println!("\nBlocks we have that BN doesn't:");
        for (&start, &end) in &blocks {
            if !expected_blocks.iter().any(|(s, _)| *s == start) {
                println!("0x{:x} - 0x{:x}", start, end);
            }
        }
    }
}
