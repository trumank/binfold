use crate::DebugContext;
use anyhow::{Context, Result, bail};
use memmap2::Mmap;
use object::pe::{IMAGE_DIRECTORY_ENTRY_EXCEPTION, ImageNtHeaders64};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::ops::Range;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RuntimeFunction {
    pub range: Range<usize>,
    pub unwind: usize,
}

#[derive(Debug, Clone)]
pub struct FunctionRange {
    pub start: u64,
    pub end: u64,
}

pub struct PeLoader {
    mmap: Mmap,
    pub image_base: u64,
}

impl PeLoader {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        // Parse PE headers to get image base
        let pe_file = PeFile::<ImageNtHeaders64>::parse(&*mmap)?;
        let image_base = pe_file.nt_headers().optional_header().image_base();

        Ok(Self { mmap, image_base })
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Convert RVA to file offset
    pub fn rva_to_file_offset(&self, rva: u64) -> Result<usize> {
        let pe_file = PeFile::<ImageNtHeaders64>::parse(&*self.mmap)?;

        // Get the raw section headers to access the VirtualAddress field directly
        let section_table = pe_file.section_table();
        for section_header in section_table.iter() {
            let section_rva = section_header.virtual_address.get(object::LittleEndian) as u64;
            let section_size = section_header
                .virtual_size
                .get(object::LittleEndian)
                .max(section_header.size_of_raw_data.get(object::LittleEndian))
                as u64;

            if rva >= section_rva && rva < section_rva + section_size {
                // Found the section
                let offset_in_section = rva - section_rva;
                let file_offset = section_header.pointer_to_raw_data.get(object::LittleEndian)
                    as u64
                    + offset_in_section;
                return Ok(file_offset as usize);
            }
        }

        bail!("RVA 0x{:x} not found in any section", rva)
    }

    /// Read bytes at a given virtual address
    pub fn read_at_va(&self, va: u64, size: usize) -> Result<&[u8]> {
        // Convert VA to RVA
        let rva = va.saturating_sub(self.image_base);
        let file_offset = self.rva_to_file_offset(rva)?;

        // Bounds check
        if file_offset + size > self.mmap.len() {
            bail!("Read would go past end of file");
        }

        Ok(&self.mmap[file_offset..file_offset + size])
    }

    /// Find a function at the given address and return its approximate size
    /// Uses recursive descent to follow all code paths
    pub fn find_function_size(&self, va: u64, ctx: &DebugContext) -> Result<usize> {
        use iced_x86::{Decoder, DecoderOptions, FlowControl};
        use std::collections::{HashSet, VecDeque};

        let max_scan = 0x10000; // Maximum function size to scan (64KB)
        let tail_call_threshold = 0x100;

        let start_offset = self.rva_to_file_offset(va.saturating_sub(self.image_base))?;

        // Adjust max_scan if it would go past end of file
        let available = self.mmap.len().saturating_sub(start_offset);
        let scan_size = max_scan.min(available);

        if scan_size == 0 {
            bail!("No bytes available to scan");
        }

        let bytes = &self.mmap[start_offset..start_offset + scan_size];

        if ctx.debug_size {
            println!("Scanning function size starting at 0x{:x}", va);
            println!("  Scan range: 0x{:x} bytes", scan_size);
        }

        // First decode all instructions in the scan range
        // let mut all_instructions = std::collections::BTreeMap::new();
        let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);

        // Now do recursive descent to find all reachable instructions
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut tailcall_queue = VecDeque::new();

        queue.push_back((va, None));

        let mut max_address = va;

        if ctx.debug_size {
            println!("\nStarting recursive descent from 0x{:x}", va);
        }

        while let Some((ip, from)) = queue.pop_front() {
            if ctx.debug_size {
                if let Some(from) = from {
                    println!("  Disassembing @ 0x{ip:x} (from 0x{from:x})",);
                } else {
                    println!("  Disassembing @ 0x{ip:x}",);
                }
            }

            if ip
                .checked_sub(va)
                .and_then(|pos| decoder.set_position(pos as usize).ok())
                .is_some()
            {
                decoder.set_ip(ip);
            } else {
                if ctx.debug_size {
                    println!("  Out of function bounds: 0x{ip:x}");
                }
                continue;
            }
            while decoder.can_decode() && !visited.contains(&decoder.ip()) {
                let instruction = decoder.decode();
                let ip = instruction.ip();
                visited.insert(ip);

                if ctx.debug_size {
                    use iced_x86::Formatter;
                    let mut formatter = iced_x86::NasmFormatter::new();
                    let mut output = String::new();
                    formatter.format(&instruction, &mut output);
                    println!(
                        "    +{:<5x} 0x{:x}: {} (flow: {:?})",
                        ip - va,
                        ip,
                        output,
                        instruction.flow_control()
                    );
                }

                // Update max address - but not for returns or interrupts
                match instruction.flow_control() {
                    FlowControl::Return | FlowControl::Interrupt => {
                        // For returns and interrupts, the current instruction end is the max
                        if ip + instruction.len() as u64 > max_address {
                            max_address = ip + instruction.len() as u64;
                        }
                    }
                    _ => {
                        // For other instructions, track the next address
                        let next_addr = decoder.ip();
                        if next_addr > max_address {
                            max_address = next_addr;
                        }
                    }
                }

                match instruction.flow_control() {
                    FlowControl::Next => {
                        // Continue to next instruction
                    }
                    FlowControl::Call | FlowControl::IndirectCall => {
                        // For calls, always continue to next instruction
                        // (both direct and indirect calls return to the next instruction)
                    }
                    FlowControl::UnconditionalBranch => {
                        // Check if it's a tail call (jmp to external function)
                        if let Some(target) = get_branch_target(&instruction)
                            && target >= va
                            && target < va + scan_size as u64
                        {
                            // Internal jump - follow it
                            tailcall_queue.push_back((target, Some(ip)));
                        }
                        break;
                        // External jump - end of function
                    }
                    FlowControl::ConditionalBranch => {
                        // Follow both paths
                        if let Some(target) = get_branch_target(&instruction)
                            && target >= va
                            && target < va + scan_size as u64
                        {
                            // Internal jump - follow it
                            queue.push_back((target, Some(ip)));
                        }
                    }
                    FlowControl::Return => {
                        // Return instruction - path ends here
                        // println!("    -> Return: path ends");
                        break;
                    }
                    FlowControl::IndirectBranch => {
                        // Indirect jump (like jmp rax or jmp [rax])
                        // We can't determine the target statically, but we should
                        // at least handle known patterns
                        if ctx.debug_size {
                            println!("  Found indirect branch at 0x{:x}", ip);
                        }
                        // For now, we can't follow indirect jumps
                        // This is a limitation that might cause us to miss code
                        break;
                    }
                    _ => {
                        if ctx.debug_size {
                            println!(
                                "  Unhandled flow control {:?} at 0x{:x}",
                                instruction.flow_control(),
                                ip
                            );
                        }
                        break;
                    }
                }
            }

            tailcall_queue.retain(|item| {
                if item.0 < max_address + tail_call_threshold {
                    queue.push_back(item.clone());
                    false
                } else {
                    true
                }
            });
        }

        let size = (max_address - va) as usize;
        if size == 0 {
            bail!("Could not determine function size")
        }

        if ctx.debug_size {
            println!("\nFunction size analysis complete:");
            println!("  Start: 0x{:x}", va);
            println!("  End: 0x{:x}", max_address);
            println!("  Size: 0x{:x} bytes", size);
            println!("  Visited {} instructions", visited.len());
        }

        Ok(size)
    }

    /// Get the exception directory range
    pub fn get_exception_directory_range(&self) -> Result<Range<usize>> {
        let pe_file = PeFile::<ImageNtHeaders64>::parse(&*self.mmap)?;
        let exception_directory = pe_file
            .data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            .context("No exception directory")?;

        let (address, size) = exception_directory.address_range();
        let start_offset = self.rva_to_file_offset(address as u64)?;
        let end_offset = start_offset + size as usize;

        Ok(start_offset..end_offset)
    }

    /// Read a u32 little-endian value at the given offset
    fn read_u32_le(&self, offset: usize) -> Result<u32> {
        if offset + 4 > self.mmap.len() {
            bail!("Read would go past end of file");
        }
        Ok(u32::from_le_bytes([
            self.mmap[offset],
            self.mmap[offset + 1],
            self.mmap[offset + 2],
            self.mmap[offset + 3],
        ]))
    }

    /// Read a u8 value at the given offset
    fn read_u8(&self, offset: usize) -> Result<u8> {
        if offset >= self.mmap.len() {
            bail!("Read would go past end of file");
        }
        Ok(self.mmap[offset])
    }

    /// Parse a runtime function entry from the exception directory
    fn parse_runtime_function(&self, offset: usize) -> Result<RuntimeFunction> {
        let start_rva = self.read_u32_le(offset)?;
        let end_rva = self.read_u32_le(offset + 4)?;
        let unwind_rva = self.read_u32_le(offset + 8)?;

        Ok(RuntimeFunction {
            range: (self.image_base + start_rva as u64) as usize
                ..(self.image_base + end_rva as u64) as usize,
            unwind: (self.image_base + unwind_rva as u64) as usize,
        })
    }

    /// Find all functions from the exception directory
    pub fn find_all_functions_from_exception_directory(&self) -> Result<Vec<FunctionRange>> {
        let exception_range = self.get_exception_directory_range()?;
        let entry_size = 12; // Each RUNTIME_FUNCTION entry is 12 bytes

        // First pass: parse all runtime functions
        let mut runtime_functions = Vec::new();
        let mut exception_children_cache: HashMap<usize, Vec<RuntimeFunction>> = HashMap::new();

        // Parse all entries in the exception directory
        let mut offset = exception_range.start;
        while offset + entry_size <= exception_range.end {
            let func = self.parse_runtime_function(offset)?;
            exception_children_cache.insert(func.range.start, vec![]);
            runtime_functions.push(func.clone());
            offset += entry_size;
        }

        // Second pass: build parent-child relationships based on unwind info
        for func in &runtime_functions {
            // Try to parse unwind info to find chained exceptions
            if let Ok(unwind_offset) =
                self.rva_to_file_offset((func.unwind as u64).saturating_sub(self.image_base))
            {
                // Check if this has chain info (first byte's upper 5 bits == 0x4)
                if let Ok(flags) = self.read_u8(unwind_offset) {
                    let has_chain_info = (flags >> 3) == 0x4;

                    if has_chain_info {
                        // Read unwind code count
                        if let Ok(unwind_code_count) = self.read_u8(unwind_offset + 2) {
                            let mut chain_offset =
                                unwind_offset + 4 + 2 * unwind_code_count as usize;

                            // Align to 4 bytes
                            if chain_offset % 4 != 0 {
                                chain_offset += 2;
                            }

                            // Parse chained runtime function
                            if chain_offset + 12 <= self.mmap.len() {
                                if let Ok(chained) = self.parse_runtime_function(chain_offset) {
                                    exception_children_cache
                                        .entry(chained.range.start)
                                        .or_default()
                                        .push(func.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Find root functions (functions that are not children of any other function)
        let mut root_functions = HashSet::new();
        for start_addr in exception_children_cache.keys() {
            root_functions.insert(*start_addr);
        }

        for children in exception_children_cache.values() {
            for child in children {
                root_functions.remove(&child.range.start);
            }
        }

        // For each root function, find all its children and determine the complete range
        let mut function_ranges = Vec::new();

        for &root_start in &root_functions {
            let mut all_functions = vec![];
            let mut queue = vec![root_start];
            let mut visited = HashSet::new();

            // Find all children recursively
            while let Some(addr) = queue.pop() {
                if visited.contains(&addr) {
                    continue;
                }
                visited.insert(addr);

                // Find the runtime function for this address
                if let Some(func) = runtime_functions.iter().find(|f| f.range.start == addr) {
                    all_functions.push(func.clone());

                    // Add children to queue
                    if let Some(children) = exception_children_cache.get(&addr) {
                        for child in children {
                            queue.push(child.range.start);
                        }
                    }
                }
            }

            // Calculate the overall range
            if !all_functions.is_empty() {
                let min_start = all_functions.iter().map(|f| f.range.start).min().unwrap();
                let max_end = all_functions.iter().map(|f| f.range.end).max().unwrap();

                function_ranges.push(FunctionRange {
                    start: min_start as u64,
                    end: max_end as u64,
                });
            }
        }

        // Sort by start address
        function_ranges.sort_by_key(|f| f.start);

        Ok(function_ranges)
    }
}

fn get_branch_target(instruction: &iced_x86::Instruction) -> Option<u64> {
    use iced_x86::OpKind;

    match instruction.op_kind(0) {
        OpKind::NearBranch16 => Some(instruction.near_branch16() as u64),
        OpKind::NearBranch32 => Some(instruction.near_branch32() as u64),
        OpKind::NearBranch64 => Some(instruction.near_branch64()),
        _ => None,
    }
}
