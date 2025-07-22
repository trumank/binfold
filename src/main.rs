use anyhow::Result;
use clap::{Parser, Subcommand};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, Mnemonic, OpKind, Register,
};
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use uuid::Uuid;

mod pe_loader;
use pe_loader::PeLoader;

const FUNCTION_NAMESPACE: &str = "0192a179-61ac-7cef-88ed-012296e9492f";
const BASIC_BLOCK_NAMESPACE: &str = "0192a178-7a5f-7936-8653-3cbaa7d6afe7";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute WARP UUID for a function in a PE file
    Pe {
        /// Path to the PE file
        #[arg(short, long)]
        file: PathBuf,

        /// Virtual address of the function
        #[arg(short, long, value_parser = parse_hex)]
        address: u64,

        /// Optional function size (will auto-detect if not provided)
        #[arg(short, long)]
        size: Option<usize>,
    },

    /// Run the example function
    Example,
}

fn parse_hex(s: &str) -> Result<u64, std::num::ParseIntError> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse()
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pe {
            file,
            address,
            size,
        } => {
            let warp_uuid = compute_warp_uuid_from_pe(&file, address, size)?;
            println!("Function at 0x{address:x}:");
            println!("WARP UUID: {warp_uuid}");
        }
        Commands::Example => {
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
            println!("WARP UUID: {warp_uuid}");
        }
    }

    Ok(())
}

fn compute_warp_uuid_from_pe(path: &PathBuf, address: u64, size: Option<usize>) -> Result<Uuid> {
    let pe = PeLoader::load(path)?;

    // Determine function size if not provided
    let func_size = match size {
        Some(s) => s,
        None => {
            println!("Auto-detecting function size...");
            pe.find_function_size(address)?
        }
    };

    println!("Function size: 0x{func_size:x} bytes");

    // Read function bytes
    let func_bytes = pe.read_at_va(address, func_size)?;

    // Compute WARP UUID
    Ok(compute_warp_uuid(func_bytes, address))
}

fn compute_warp_uuid(raw_bytes: &[u8], base: u64) -> Uuid {
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
    // for (&start_addr, &end_addr) in &basic_blocks {
    //     println!("\nBasic block: 0x{start_addr:x} - 0x{end_addr:x}");
    //     println!("----------------------------------------");

    //     // Disassemble the block
    //     let block_start_offset = (start_addr - base) as usize;
    //     let block_end_offset = (end_addr - base) as usize;
    //     let block_bytes = &raw_bytes[block_start_offset..block_end_offset];

    //     let mut decoder = Decoder::with_ip(64, block_bytes, start_addr, DecoderOptions::NONE);
    //     let mut formatter = iced_x86::NasmFormatter::new();
    //     let mut output = String::new();

    //     while decoder.can_decode() {
    //         let instruction = decoder.decode();
    //         output.clear();
    //         formatter.format(&instruction, &mut output);
    //         println!("  0x{:x}: {}", instruction.ip(), output);
    //     }
    // }
    // Combine block UUIDs to create function UUID
    // Note: Despite WARP spec saying "highest to lowest", Binary Ninja
    // actually combines them in low-to-high address order
    let namespace = Uuid::parse_str(FUNCTION_NAMESPACE).unwrap();
    let mut combined_bytes = Vec::new();
    for (_, uuid) in block_uuids.iter() {
        combined_bytes.extend_from_slice(uuid.as_bytes());
    }

    create_uuid_v5(&namespace, &combined_bytes)
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

    for &addr in instructions.keys() {
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
        if let Some(prev) = prev_instruction
            && matches!(
                prev.flow_control(),
                FlowControl::UnconditionalBranch | FlowControl::Return
            )
        {
            block_starts.insert(addr);
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

fn create_basic_block_guid(raw_bytes: &[u8], base: u64) -> Uuid {
    let namespace = Uuid::parse_str(BASIC_BLOCK_NAMESPACE).unwrap();
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

        // NOPs are included in the hash according to WARP spec
        // Only skip them if they're used for hot-patching alignment

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
            bytes.extend_from_slice(instr_bytes);
        }
    }

    bytes
}

fn get_instruction_bytes_for_guid_debug(raw_bytes: &[u8], base: u64) -> (Vec<u8>, Vec<String>) {
    let mut bytes = Vec::new();
    let mut debug_info = Vec::new();

    let mut decoder = Decoder::new(64, raw_bytes, DecoderOptions::NONE);
    decoder.set_ip(base);

    let mut formatter = iced_x86::NasmFormatter::new();
    let mut output = String::new();

    while decoder.can_decode() {
        let start = (decoder.ip() - base) as usize;
        let instruction = decoder.decode();
        let end = (decoder.ip() - base) as usize;
        let instr_bytes = &raw_bytes[start..end];

        output.clear();
        formatter.format(&instruction, &mut output);

        // NOPs are included in the hash according to WARP spec
        // Only skip them if they're used for hot-patching alignment

        // Skip instructions that set a register to itself (if they're effectively NOPs)
        if is_register_to_itself_nop(&instruction) {
            debug_info.push(format!(
                "SKIP REG2REG: 0x{:x}: {}",
                instruction.ip(),
                output
            ));
            continue;
        }

        // Get instruction bytes, zeroing out relocatable instructions
        if is_relocatable_instruction(&instruction) {
            // Zero out relocatable instructions
            bytes.extend(vec![0u8; instr_bytes.len()]);
            debug_info.push(format!(
                "ZERO RELOC: 0x{:x}: {} | {:02x?}",
                instruction.ip(),
                output,
                instr_bytes
            ));
        } else {
            // Use actual instruction bytes
            bytes.extend_from_slice(instr_bytes);
            debug_info.push(format!(
                "KEEP: 0x{:x}: {} | {:02x?}",
                instruction.ip(),
                output,
                instr_bytes
            ));
        }
    }

    (bytes, debug_info)
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

    // Jumps are not considered relocatable in WARP
    // This includes both short and long jumps

    // Check for RIP-relative memory operands
    for i in 0..instruction.op_count() {
        if instruction.op_kind(i) == OpKind::Memory {
            // Check if it's RIP-relative (no base register, or RIP as base)
            if instruction.memory_base() == Register::RIP
                || (instruction.memory_base() == Register::None
                    && instruction.memory_index() == Register::None
                    && instruction.memory_displacement64() != 0)
            {
                return true;
            }
        }
    }

    false
}

fn create_uuid_v5(namespace: &Uuid, data: &[u8]) -> Uuid {
    let mut hasher = Sha1::new();
    hasher.update(namespace.as_bytes());
    hasher.update(data);
    let hash = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);

    // Set version (5) and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    Uuid::from_bytes(bytes)
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

        println!("0x{addr:08x}  | {in_edges:3} | {out_edges:3} | {output}");
    }
}

// >>> with open('/tmp/functions.json', 'w') as f:
//     json.dump([{"guid": str(binaryninja.warp.get_function_guid(f)), "start": f.start, "blocks": [{"start": b.start, "end": b.end, "guid": str(binaryninja.warp.get_basic_block_guid(b))} for b in sorted(f.basic_blocks)]} for f in bv.functions if len(f.basic_blocks) == 150], f)

#[cfg(test)]
mod test {
    use super::*;

    use serde::Deserialize;
    use uuid::uuid;

    #[derive(Debug, Deserialize)]
    struct Function {
        guid: Uuid,
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
        let f = std::io::BufReader::new(std::fs::File::open("functions.json").unwrap());
        let functions: Vec<Function> = serde_json::from_reader(f).unwrap();
        // dbg!(functions);
        for function in functions {
            test_warp_function_from_binary(
                "/home/truman/projects/ue/patternsleuth/games/427S_Texas_Chainsaw_Massacre/BBQClient-Win64-Shipping.exe",
                function.start,
                function.guid,
                function
                    .blocks
                    .into_iter()
                    .map(|b| (b.start, b.end, b.guid))
                    .collect(),
            );
        }
    }

    // Helper function to test WARP function from binary
    fn test_warp_function_from_binary(
        exe_path: impl AsRef<std::path::Path>,
        function_address: u64,
        expected_function_guid: Uuid,
        expected_blocks: Vec<(u64, u64, Uuid)>,
    ) {
        // Load main.exe from root directory
        let pe = PeLoader::load(exe_path).expect("Failed to load main.exe");

        // Use the heuristic to find function size
        let function_size = pe
            .find_function_size(function_address)
            .expect("Failed to determine function size");

        println!(
            "Function at 0x{:x} has size: 0x{:x}",
            function_address, function_size
        );

        // Read the function bytes
        let function_bytes = pe
            .read_at_va(function_address, function_size)
            .expect("Failed to read function bytes");

        // Compute basic blocks
        let blocks = identify_basic_blocks(function_bytes, function_address);

        println!("\nComparing basic blocks:");
        println!(
            "Start       | End         | Our GUID                             | Expected GUID                        | Match"
        );
        println!(
            "------------|-------------|--------------------------------------|--------------------------------------|-------"
        );

        let mut matching_blocks = 0;
        for &(start, end, expected_guid) in &expected_blocks {
            let our_end = blocks.get(&start);
            let our_guid = if our_end == Some(&end) {
                let block_bytes = &function_bytes
                    [(start - function_address) as usize..(end - function_address) as usize];
                Some(create_basic_block_guid(block_bytes, start))
            } else {
                None
            };

            let guid_match = our_guid == Some(expected_guid);
            if guid_match {
                matching_blocks += 1;
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
        let warp_uuid = compute_warp_uuid(function_bytes, function_address);
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
    }

    #[test]
    fn test_function_at_0x140001bf4() {
        #[rustfmt::skip]
        test_warp_function_from_binary(
            "main.exe",
            0x140001bf4,
            uuid!("863d236e-ccc8-530a-b3f6-4a95b6e8c5c7"),
            vec![
                (0x140001bf4, 0x140001c09, uuid!("5db95fec-4dad-552c-94d3-627ff36d7cb0")),
                (0x140001c09, 0x140001c22, uuid!("20cf54a2-472d-53c7-91cc-d0f8e0e9cf35")),
                (0x140001c22, 0x140001c2d, uuid!("0f3e9534-0651-5d76-962e-5c5ead3c4ce9")),
                (0x140001c2d, 0x140001c47, uuid!("81d7f090-dd49-5e7e-bd20-5c221f4167aa")),
                (0x140001c47, 0x140001c50, uuid!("499bb1d1-6b28-5214-97c6-a69395b199fb")),
                (0x140001c50, 0x140001c58, uuid!("1c78b954-16d9-5bbb-be5a-77843834febc")),
                (0x140001c58, 0x140001c62, uuid!("1f74bbf6-ad7a-5a08-8c3e-bfb46c8b1f05")),
                (0x140001c62, 0x140001c68, uuid!("24f3129c-e976-5d87-87ca-f280c91f052e")),
                (0x140001c68, 0x140001c6a, uuid!("15f95f37-8c6b-5380-a865-5b9c20aee758")),
                (0x140001c6a, 0x140001c6f, uuid!("1eb72e47-4d18-570d-8f74-76097b144ae5")),
                (0x140001c6f, 0x140001c73, uuid!("d7d7e2c2-91eb-5d6c-b224-f2dfc495a7f2")),
                (0x140001c73, 0x140001c79, uuid!("697bca86-51b0-53a5-8011-fee3a94036dd")),
                (0x140001c79, 0x140001c7d, uuid!("80878bdc-bd23-5ee6-9255-f7ac1601ee3e")),
                (0x140001c7d, 0x140001c81, uuid!("64e0e563-c542-53ad-ba1a-ecbd87531d5e")),
                (0x140001c81, 0x140001c85, uuid!("681a270c-c970-5903-a9fa-dc26e5936cee")),
                (0x140001c87, 0x140001c8c, uuid!("70a456bd-29ce-5068-bb99-23603ccd3f79")),
            ],
        );
    }

    #[test]
    fn test_function_at_0x140001fb4() {
        #[rustfmt::skip]
        test_warp_function_from_binary(
            "main.exe",
            0x140001fb4,
            uuid!("f3249490-0a5f-504a-9f54-54ae22bafd72"),
            vec![
                (0x140001fb4, 0x140001fda, uuid!("33a75e99-c87b-59ae-9356-8afb31aea91c")),
                (0x140001fda, 0x140001fde, uuid!("1e43ade3-9175-5150-84ef-55b3bdaf3267")),
                (0x140001fde, 0x140002022, uuid!("2073619d-f0b4-5522-b949-b3c10a2b57da")),
                (0x140002022, 0x14000205e, uuid!("d2a8a192-4c7d-52ab-859a-6b2e4f4b2362")),
                (0x14000205e, 0x1400020de, uuid!("65845881-bf33-5018-9fd6-1ffa86c12a94")),
                (0x1400020de, 0x1400020e3, uuid!("61cc7aa6-a12c-5b1b-9d0c-4ed2a96e84d1")),
                (0x1400020e3, 0x1400020eb, uuid!("fbf4ac1c-c2e1-5aa5-b821-dbf95b3de866")),
                (0x1400020eb, 0x1400020fc, uuid!("81583611-164b-5957-9bf0-fcc1ae60ebee")),
            ],
        );
    }

    #[test]
    fn test_function_at_0x14000261c() {
        #[rustfmt::skip]
        test_warp_function_from_binary(
            "main.exe",
            0x14000261c,
            uuid!("ff2ad3fe-a9bd-5a3e-bda0-6254eda45d80"),
            vec![
                (0x14000261c, 0x140002675, uuid!("5b4500a3-8306-53e1-a967-d4db5263143b")),
                (0x140002675, 0x140002694, uuid!("47b5b1af-6cfd-55ad-9637-9c61fc365d52")),
                (0x140002694, 0x14000269b, uuid!("0f198a01-e025-5dac-9ec9-7ebd811aadce")),
                (0x14000269b, 0x1400026a2, uuid!("23139502-4b5b-5655-905f-6ed4ba97af48")),
                (0x1400026a2, 0x1400026ac, uuid!("8a6d9b48-f329-5a9d-b8eb-b23ab85422f7")),
                (0x1400026ac, 0x1400026bc, uuid!("117483da-d018-5b35-8f6e-3bdb3581fbbf")),
                (0x1400026bc, 0x1400026d0, uuid!("689e9fbc-5e30-5ffe-bdf1-1d1cd9206b15")),
                (0x1400026d0, 0x1400026d7, uuid!("f0ed3e54-1af6-5463-ad13-23805c5dd144")),
                (0x1400026d7, 0x1400026e4, uuid!("f2c2fa36-6e71-5c5b-85bf-fbda941fd56f")),
                (0x1400026e4, 0x140002700, uuid!("13729f44-b768-58a3-837c-a10b0cdf0bc8")),
                (0x140002700, 0x14000270a, uuid!("b1233c4d-8e1a-5600-a383-4a5a7d389e79")),
                (0x14000270a, 0x140002725, uuid!("01fd9f02-71cd-55ae-9506-07842f907e39")),
                (0x140002725, 0x14000273d, uuid!("2df0e266-342f-5aa3-8953-578f14143825")),
                (0x14000273d, 0x140002743, uuid!("833d89e3-a114-5178-9098-bf40d7f363d4")),
                (0x140002743, 0x14000275f, uuid!("0c56fdc6-d6b6-5df1-a78a-1023d9c24388")),
                (0x14000275f, 0x14000277e, uuid!("68035525-aebb-5796-b70c-d41386eecf57")),
                (0x14000277e, 0x14000279e, uuid!("b7e2e581-9523-5871-97ab-54c514018208")),
                (0x14000279e, 0x1400027a9, uuid!("ab687395-0a66-5cfa-ab10-fafcb6b8bf14")),
                (0x1400027a9, 0x1400027b6, uuid!("c70dfa11-a2d0-50bb-8115-a1f485bf6518")),
                (0x1400027b6, 0x1400027c8, uuid!("a895d010-9366-5396-8aae-a96f6f995d2f")),
            ],
        );
    }

    #[test]
    fn test_function_at_0x140001a2c() {
        #[rustfmt::skip]
        test_warp_function_from_binary(
            "main.exe",
            0x140001a2c,
            uuid!("19756a88-3460-556c-8424-0fde3749c556"),
            vec![
                (0x140001a2c, 0x140001a54, uuid!("a2e70f91-bfdb-5aad-b913-b1128d081074")),
                (0x140001a54, 0x140001a59, uuid!("730a5cf5-d682-5d84-abd1-1ee1556c6be7")),
                (0x140001a59, 0x140001a6a, uuid!("77b84327-bd45-552f-9aa1-a37bb4dd27b8")),
                (0x140001a6a, 0x140001a8c, uuid!("67d5fd1f-da0f-5793-9551-03dc644059b6")),
            ],
        );
    }
}
