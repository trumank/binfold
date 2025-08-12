use anyhow::{Context, Result, anyhow, bail};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use iset::IntervalMap;
use memmap2::Mmap;
use object::pe::{IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_SCN_MEM_EXECUTE};
use object::read::pe::ImageNtHeaders;
use object::{File, Object, ObjectSection};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::{self};
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{debug, trace};

// PE section characteristics
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

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

#[derive(Debug, Clone)]
pub struct FunctionCall {
    /// instruction address of CALL
    pub address: u64,
    /// CALL target address
    pub target: u64,
}

#[derive(Debug, Clone)]
pub struct DataReference {
    /// instruction address
    pub address: u64,
    /// target address of data reference
    pub target: u64,
    /// whether the reference is to read-only data
    pub is_readonly: bool,
    /// estimated size of the data being referenced (based on instruction)
    pub estimated_size: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct JumpTable {
    /// start address of jump table
    start: u64,
    /// end address of jump table (exclusive)
    end: u64,
}

/// Control flow graph built during recursive descent
#[derive(Debug, Default, Clone)]
pub struct FunctionAnalysis {
    pub size: usize,
    /// Block bounds start -> end
    pub basic_blocks: BTreeMap<u64, u64>,
    pub entry_point: u64,
    pub calls: Vec<FunctionCall>,
    pub data_refs: Vec<DataReference>,
    pub jump_tables: Vec<JumpTable>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlockBound {
    Start(u64),
    End(u64),
}
impl BlockBound {
    pub fn address(&self) -> u64 {
        match self {
            BlockBound::Start(a) => *a,
            BlockBound::End(a) => *a,
        }
    }
}
impl std::cmp::Ord for BlockBound {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address()
            .cmp(&other.address())
            .then_with(|| match (self, other) {
                (BlockBound::End(_), BlockBound::Start(_)) => std::cmp::Ordering::Less,
                (BlockBound::Start(_), BlockBound::End(_)) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            })
    }
}
impl std::cmp::PartialOrd for BlockBound {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
pub struct PdbDebugInfo {
    pub guid: [u8; 16],
    pub age: u32,
}

#[derive(Debug)]
pub struct SectionInfo {
    pub name_bytes: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl SectionInfo {
    pub fn name(&self) -> Result<&str> {
        let end = self.name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        std::str::from_utf8(&self.name_bytes[..end]).context("Invalid section name")
    }
}

self_cell::self_cell!(
    struct FileData {
        owner: Mmap,
        #[covariant]
        dependent: File,
    }
);

#[derive(Default)]
pub struct AnalysisCache {
    cache: Arc<Mutex<HashMap<u64, Result<Arc<FunctionAnalysis>>>>>,
}
impl AnalysisCache {
    pub fn new(functions: impl IntoIterator<Item = FunctionAnalysis>) -> Self {
        Self {
            cache: Arc::new(Mutex::new(
                functions
                    .into_iter()
                    .map(|func| (func.entry_point, Ok(Arc::new(func))))
                    .collect(),
            )),
        }
    }
    pub fn get(&self, address: u64, pe: &PeLoader) -> Result<Arc<FunctionAnalysis>> {
        use std::collections::hash_map::Entry;
        let mut lock = self.cache.lock().unwrap();
        fn map(res: &Result<Arc<FunctionAnalysis>>) -> Result<Arc<FunctionAnalysis>> {
            res.as_ref()
                .map(|v| v.clone())
                .map_err(|e| anyhow!("cache: {e:?}"))
        }
        match lock.entry(address) {
            Entry::Occupied(entry) => map(entry.get()),
            Entry::Vacant(entry) => map(entry.insert(pe.analyze_function(address).map(Arc::new))),
        }
    }
}

pub struct PeLoader {
    file: FileData,
}

impl PeLoader {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = fs::File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        Ok(Self {
            file: FileData::try_new(mmap, |mmap| object::File::parse(mmap))?,
        })
    }

    pub fn image_base(&self) -> u64 {
        self.file.borrow_dependent().relative_address_base()
    }

    /// Get the bitness of the PE file (32 or 64)
    pub fn bitness(&self) -> u32 {
        match self.file.borrow_dependent() {
            object::File::Pe32(_) => 32,
            object::File::Pe64(_) => 64,
            _ => todo!("Unhandled File format"),
        }
    }

    /// Convert RVA to file offset
    pub fn rva_to_file_offset(&self, rva: u64) -> Result<usize> {
        let file = self.file.borrow_dependent();

        for section in file.sections() {
            let section_rva = section.address() - self.image_base();
            let section_size = section.size();

            if rva >= section_rva && rva < section_rva + section_size {
                // Found the section
                let offset_in_section = rva - section_rva;
                let file_offset = section
                    .file_range()
                    .map(|(offset, _)| offset + offset_in_section)
                    .ok_or_else(|| anyhow::anyhow!("Section has no file data"))?;
                return Ok(file_offset as usize);
            }
        }

        bail!("RVA 0x{:x} not found in any section", rva)
    }

    /// Read bytes at a given virtual address
    pub fn read_at_va(&self, va: u64, size: usize) -> Result<&[u8]> {
        // Convert VA to RVA
        let rva = va - self.image_base();
        let file_offset = self.rva_to_file_offset(rva)?;

        // Get file data
        let file_data = self.file.borrow_owner();

        // Bounds check
        if file_offset + size > file_data.len() {
            bail!("Read would go past end of file");
        }

        Ok(&file_data[file_offset..file_offset + size])
    }

    /// Find a function at the given address and return its approximate size
    /// Uses recursive descent to follow all code paths
    pub fn find_function_size(&self, va: u64) -> Result<usize> {
        self.analyze_function(va).map(|a| a.size)
    }

    pub fn analyze_function(&self, va: u64) -> Result<FunctionAnalysis> {
        let mut analysis = FunctionAnalysis {
            entry_point: va,
            ..Default::default()
        };

        let max_scan = 0x10000; // Maximum function size to scan (64KB)
        let tail_call_threshold = 0x50;

        let start_offset = self.rva_to_file_offset(va.saturating_sub(self.image_base()))?;

        // Get file data
        let file_data = self.file.borrow_owner();

        // Adjust max_scan if it would go past end of file
        let available = file_data.len().saturating_sub(start_offset);
        let scan_size = max_scan.min(available);

        if scan_size == 0 {
            bail!("No bytes available to scan");
        }

        let bytes = &file_data[start_offset..start_offset + scan_size];

        debug!(
            start = format!("0x{va:x}"),
            scan_range = format!("0x{scan_size:x}"),
            "Scanning function size"
        );

        // First decode all instructions in the scan range
        // let mut all_instructions = std::collections::BTreeMap::new();
        let bitness = self.bitness();
        let mut decoder = Decoder::with_ip(bitness, bytes, va, DecoderOptions::NONE);

        // Now do recursive descent to find all reachable instructions
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut tailcall_queue = VecDeque::new();
        let mut block_intervals: BTreeSet<BlockBound> = Default::default();

        queue.push_back((va, None));

        let mut max_address = va;

        block_intervals.insert(BlockBound::Start(va));

        debug!(start = format!("0x{va:x}"), "Starting recursive descent");

        while let Some((ip, from)) = queue.pop_front() {
            trace!(
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
                    target: "binfold::pe_loader::size",
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
                                    !self.is_address_writable(target_address).unwrap_or(false);
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
                        // Check if it's a tail call (jmp to external function)
                        if let Some(target) = get_branch_target(&instruction)
                            && target >= va
                            && target < va + scan_size as u64
                        {
                            // Unknown if tail call, defer analysis
                            tailcall_queue.push_back((target, Some(ip)));
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
                        // Indirect jump (like jmp rax or jmp [rax])
                        // Try to detect jump table patterns
                        if let Some((table, jump_targets)) =
                            detect_jump_table_targets(&instruction, self)
                        {
                            trace!(
                                address = format!("0x{ip:x}"),
                                targets = jump_targets.len(),
                                "Found jump table with targets"
                            );

                            // Add all jump table targets to the queue for analysis
                            for &target in &jump_targets {
                                if target >= va && target < va + scan_size as u64 {
                                    queue.push_back((target, Some(ip)));
                                    block_intervals.insert(BlockBound::Start(target));
                                }
                            }

                            analysis.jump_tables.push(table);
                        } else {
                            trace!(
                                address = format!("0x{ip:x}"),
                                "Found indirect branch (no jump table detected)"
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
                if target < max_address + tail_call_threshold {
                    // Internal jump
                    block_intervals.insert(BlockBound::Start(target));
                    queue.push_back(*item);
                    false
                } else {
                    // Tail call
                    analysis.calls.push(FunctionCall {
                        address: ip,
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
            start = format!("0x{va:x}"),
            end = format!("0x{max_address:x}"),
            size = format!("0x{size:x}"),
            "Function size analysis complete"
        );

        Ok(analysis)
    }

    /// Get the exception directory range
    pub fn get_exception_directory_range(&self) -> Result<Option<Range<usize>>> {
        let file = self.file.borrow_dependent();
        let Some(exception_directory) = (match file {
            object::File::Pe32(pe_file) => pe_file.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION),
            object::File::Pe64(pe_file) => pe_file.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION),
            _ => bail!("Only PE32/PE64 files are supported"),
        }) else {
            return Ok(None);
        };

        let (address, size) = exception_directory.address_range();
        let start_offset = self.rva_to_file_offset(address as u64)?;
        let end_offset = start_offset + size as usize;

        Ok(Some(start_offset..end_offset))
    }

    /// Read a u32 little-endian value at the given offset
    fn read_u32_le(&self, offset: usize) -> Result<u32> {
        let file_data = self.file.borrow_owner();
        if offset + 4 > file_data.len() {
            bail!("Read would go past end of file");
        }
        Ok(u32::from_le_bytes(
            file_data[offset..offset + 4].try_into().unwrap(),
        ))
    }

    /// Read a u8 value at the given offset
    fn read_u8(&self, offset: usize) -> Result<u8> {
        let file_data = self.file.borrow_owner();
        if offset >= file_data.len() {
            bail!("Read would go past end of file");
        }
        Ok(file_data[offset])
    }

    /// Parse a runtime function entry from the exception directory
    fn parse_runtime_function(&self, offset: usize) -> Result<RuntimeFunction> {
        let start_rva = self.read_u32_le(offset)?;
        let end_rva = self.read_u32_le(offset + 4)?;
        let unwind_rva = self.read_u32_le(offset + 8)?;

        Ok(RuntimeFunction {
            range: (self.image_base() + start_rva as u64) as usize
                ..(self.image_base() + end_rva as u64) as usize,
            unwind: (self.image_base() + unwind_rva as u64) as usize,
        })
    }

    /// Find all functions from the exception directory
    pub fn find_all_functions_from_exception_directory(&self) -> Result<Vec<FunctionRange>> {
        let Some(exception_range) = self.get_exception_directory_range()? else {
            return Ok(vec![]);
        };
        let entry_size = 12; // Each RUNTIME_FUNCTION entry is 12 bytes

        // First pass: parse all runtime functions
        let mut runtime_functions_by_start: HashMap<usize, RuntimeFunction> = HashMap::new();
        let mut exception_children_cache: HashMap<usize, Vec<RuntimeFunction>> = HashMap::new();

        // Parse all entries in the exception directory
        let mut offset = exception_range.start;
        while offset + entry_size <= exception_range.end {
            let func = self.parse_runtime_function(offset)?;
            exception_children_cache.insert(func.range.start, vec![]);
            runtime_functions_by_start.insert(func.range.start, func);
            offset += entry_size;
        }

        // Second pass: build parent-child relationships based on unwind info
        for func in runtime_functions_by_start.values() {
            // Try to parse unwind info to find chained exceptions
            let unwind_offset =
                self.rva_to_file_offset((func.unwind as u64).saturating_sub(self.image_base()))?;
            // Check if this has chain info (first byte's upper 5 bits == 0x4)
            let flags = self.read_u8(unwind_offset)?;
            let has_chain_info = (flags >> 3) == 0x4;

            if has_chain_info {
                // Read unwind code count
                let unwind_code_count = self.read_u8(unwind_offset + 2)?;
                let mut chain_offset = unwind_offset + 4 + 2 * unwind_code_count as usize;

                // Align to 4 bytes
                if !chain_offset.is_multiple_of(4) {
                    chain_offset += 2;
                }

                // Parse chained runtime function
                if chain_offset + 12 <= self.file.borrow_owner().len() {
                    let chained = self.parse_runtime_function(chain_offset)?;
                    exception_children_cache
                        .entry(chained.range.start)
                        .or_default()
                        .push(func.clone());
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

                // Find the runtime function for this address using O(1) HashMap lookup
                if let Some(func) = runtime_functions_by_start.get(&addr) {
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

    /// Get the timestamp from the PE header
    pub fn timestamp(&self) -> Result<u32> {
        let file = self.file.borrow_dependent();
        Ok(match file {
            object::File::Pe32(pe_file) => pe_file.nt_headers().file_header(),
            object::File::Pe64(pe_file) => pe_file.nt_headers().file_header(),
            _ => bail!("Only PE32/PE64 files are supported"),
        }
        .time_date_stamp
        .get(object::LittleEndian))
    }

    /// Get PDB debug info from the PE file
    pub fn pdb_info(&self) -> Result<PdbDebugInfo> {
        use object::LittleEndian as LE;
        use object::pe::{
            IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DIRECTORY_ENTRY_DEBUG, ImageDebugDirectory,
        };

        let file = self.file.borrow_dependent();
        let data_dirs = match file {
            object::File::Pe32(pe_file) => pe_file.data_directories(),
            object::File::Pe64(pe_file) => pe_file.data_directories(),
            _ => bail!("Only PE32/PE64 files are supported"),
        };

        // Get debug directory
        let debug_dir = data_dirs
            .get(IMAGE_DIRECTORY_ENTRY_DEBUG)
            .ok_or_else(|| anyhow::anyhow!("No debug directory"))?;

        // Convert RVA to file offset
        let debug_rva = debug_dir.virtual_address.get(LE);
        let debug_offset = self.rva_to_file_offset(debug_rva as u64)?;
        let debug_size = debug_dir.size.get(LE) as usize;

        let file_data = self.file.borrow_owner();
        if debug_offset + debug_size > file_data.len() {
            bail!("Debug directory extends past end of file");
        }

        let debug_data = &file_data[debug_offset..debug_offset + debug_size];

        // Parse debug directory entries
        let num_entries =
            debug_dir.size.get(LE) as usize / std::mem::size_of::<ImageDebugDirectory>();
        let entries = object::slice_from_bytes::<ImageDebugDirectory>(debug_data, num_entries)
            .map_err(|_| anyhow::anyhow!("Failed to parse debug directory entries"))?
            .0;

        // Find CodeView entry
        for entry in entries {
            if entry.typ.get(LE) == IMAGE_DEBUG_TYPE_CODEVIEW {
                let offset = entry.pointer_to_raw_data.get(LE) as usize;
                let size = entry.size_of_data.get(LE) as usize;

                if offset + size > file_data.len() {
                    bail!("Invalid debug data offset");
                }

                let debug_data = &file_data[offset..offset + size];

                // Parse CodeView data
                if debug_data.len() < 24 {
                    bail!("CodeView data too small");
                }

                let signature = u32::from_le_bytes(debug_data[0..4].try_into()?);
                if signature != 0x53445352 {
                    // "RSDS"
                    bail!("Invalid CodeView signature");
                }

                let mut guid = [0u8; 16];
                guid.copy_from_slice(&debug_data[4..20]);
                let age = u32::from_le_bytes(debug_data[20..24].try_into()?);

                return Ok(PdbDebugInfo { guid, age });
            }
        }

        bail!("No CodeView debug info found")
    }

    /// Get an iterator over PE sections
    pub fn sections(&self) -> impl Iterator<Item = SectionInfo> + '_ {
        let file = self.file.borrow_dependent();

        match file {
            object::File::Pe32(pe_file) => pe_file.section_table(),
            object::File::Pe64(pe_file) => pe_file.section_table(),
            _ => panic!("Only PE32/PE64 files are supported"),
        }
        .iter()
        .map(|section: &object::pe::ImageSectionHeader| SectionInfo {
            name_bytes: section.name,
            virtual_address: section.virtual_address.get(object::LittleEndian),
            virtual_size: section.virtual_size.get(object::LittleEndian),
            size_of_raw_data: section.size_of_raw_data.get(object::LittleEndian),
            pointer_to_raw_data: section.pointer_to_raw_data.get(object::LittleEndian),
            characteristics: section.characteristics.get(object::LittleEndian),
        })
    }

    /// Check if a virtual address falls within any section of the image
    pub fn is_address_in_section(&self, va: u64) -> bool {
        let image_base = self.image_base();
        if va < image_base {
            return false;
        }

        let rva = va - image_base;

        // Check if the RVA falls within any section
        for section in self.sections() {
            let section_start = section.virtual_address as u64;
            let section_end = section_start + section.virtual_size as u64;
            if rva >= section_start && rva < section_end {
                return true;
            }
        }
        false
    }

    /// Check if a virtual address is in a writable section
    pub fn is_address_writable(&self, va: u64) -> Result<bool> {
        let rva = va.saturating_sub(self.image_base());

        for section in self.sections() {
            let section_start = section.virtual_address as u64;
            let section_end = section_start + section.virtual_size as u64;

            if rva >= section_start && rva < section_end {
                return Ok((section.characteristics & IMAGE_SCN_MEM_WRITE) != 0);
            }
        }

        // Address not found in any section
        Ok(false)
    }

    /// Find functions using linear sweep through executable sections
    /// This serves as a fallback when exception directory is not available
    pub fn find_functions_linear_sweep(&self) -> Result<Vec<FunctionAnalysis>> {
        let mut function_analysis = BTreeMap::new();
        // map address range => entry point
        let mut function_map = IntervalMap::<u64, Option<u64>>::new();

        // Process all executable sections
        for section in self.sections() {
            // Skip non-executable sections
            if (section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 {
                continue;
            }

            // Skip writable sections (likely data, not code)
            if (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0 {
                continue;
            }

            let section_va = self.image_base() + section.virtual_address as u64;
            let section_size = section.virtual_size as u64;

            debug!(
                section = section.name().unwrap_or("<invalid>"),
                start = format!("0x{section_va:x}"),
                size = format!("0x{section_size:x}"),
                "Scanning executable section"
            );

            // Get section data
            let section_data = match self.read_at_va(section_va, section_size as usize) {
                Ok(data) => data,
                Err(e) => {
                    debug!(
                        section = section.name().unwrap_or("<invalid>"),
                        error = %e,
                        "Failed to read section data"
                    );
                    continue;
                }
            };

            let bitness = self.bitness();
            let mut decoder =
                Decoder::with_ip(bitness, section_data, section_va, DecoderOptions::NONE);
            let mut potential_functions = HashSet::new();

            // First pass: identify potential function start points
            while decoder.can_decode() {
                let instruction = decoder.decode();
                let ip = instruction.ip();

                // Look for call targets within this section
                if matches!(
                    instruction.flow_control(),
                    FlowControl::Call //| FlowControl::UnconditionalBranch
                ) && let Some(target) = get_branch_target(&instruction)
                {
                    potential_functions.insert(target);
                    trace!(
                        caller = format!("0x{ip:x}"),
                        target = format!("0x{target:x}"),
                        "Call target identified as function"
                    );
                }
            }

            // Second pass: validate and size each potential function
            for &func_start in &potential_functions {
                if function_map.has_overlap(func_start..func_start + 1) {
                    continue;
                }

                match self.analyze_function(func_start) {
                    Ok(func) => {
                        let func_end = func_start + func.size as u64;

                        debug!(
                            start = format!("0x{func_start:x}"),
                            end = format!("0x{func_end:x}"),
                            size = format!("0x{:x}", func.size),
                            "Function discovered via linear sweep"
                        );

                        if function_map.has_overlap(func_start..func_end) {
                            debug!(
                                start = format!("0x{func_start:x}"),
                                end = format!("0x{func_end:x}"),
                                size = format!("0x{:x}", func.size),
                                "Function already exists at"
                            );
                        } else {
                            function_map.insert(func_start..func_end, Some(func_start));
                            assert_eq!(func.entry_point, func_start);
                            function_analysis.insert(func.entry_point, func);
                        }
                    }
                    Err(e) => {
                        trace!(
                            address = format!("0x{func_start:x}"),
                            error = %e,
                            "Failed to determine function size"
                        );
                    }
                }
            }
        }

        // After linear sweep, check for gaps and scan them for functions
        for section in self.sections() {
            // Skip non-executable sections
            if (section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 {
                continue;
            }

            // Skip writable sections (likely data, not code)
            if (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0 {
                continue;
            }

            let section_va = self.image_base() + section.virtual_address as u64;
            let section_size = section.virtual_size as u64;
            let section_end = section_va + section_size;

            debug!(
                section = section.name().unwrap_or("<invalid>"),
                start = format!("0x{section_va:x}"),
                size = format!("0x{section_size:x}"),
                "Scanning gaps in executable section"
            );

            // Find gaps in the function map within this section
            let mut gaps = Vec::new();
            let mut last_end = section_va;

            // Collect all intervals in this section and sort them
            let intervals_in_section = function_map.intervals(section_va..section_end);

            // Find gaps between intervals
            for interval in intervals_in_section {
                if interval.start > last_end {
                    gaps.push(last_end..interval.start);
                }
                last_end = last_end.max(interval.end);
            }

            // Add gap at the end if needed
            if last_end < section_end {
                gaps.push(last_end..section_end);
            }

            for gap in gaps {
                let gap_start = gap.start;
                let gap_size = gap.end - gap.start;

                trace!(
                    gap_start = format!("0x{gap_start:x}"),
                    gap_end = format!("0x{:x}", gap.end),
                    gap_size = format!("0x{gap_size:x}"),
                    "Found gap in function map"
                );

                // Scan the gap for potential function entry points
                let gap_data = self.read_at_va(gap_start, gap_size as usize)?;
                let mut gap_decoder =
                    Decoder::with_ip(self.bitness(), gap_data, gap_start, DecoderOptions::NONE);

                while gap_decoder.can_decode() {
                    let instruction = gap_decoder.decode();
                    let ip = instruction.ip();

                    let is_potential_function = instruction.mnemonic() != Mnemonic::INVALID
                        && instruction.flow_control() != FlowControl::Interrupt;

                    if is_potential_function
                        && !function_map.has_overlap(ip..ip + 1)
                        && let Ok(func) = self.analyze_function(ip)
                    {
                        let func_end = ip + func.size as u64;

                        // Ensure the function doesn't extend beyond the gap or overlap existing functions
                        if func_end <= gap.end && !function_map.has_overlap(ip..func_end) {
                            debug!(
                                start = format!("0x{ip:x}"),
                                end = format!("0x{func_end:x}"),
                                size = format!("0x{:x}", func.size),
                                "Function discovered in gap"
                            );

                            for table in &func.jump_tables {
                                function_map.insert(table.start..table.end, None);
                            }
                            function_map.insert(ip..func_end, Some(ip));
                            function_analysis.insert(func.entry_point, func);
                        }
                    }
                }
            }
        }

        let functions = function_analysis.into_values().collect::<Vec<_>>();

        tracing::info!(
            functions = functions.len(),
            "Linear sweep function discovery complete (including gaps)"
        );

        Ok(functions)
    }

    /// Find all functions using both exception directory and linear sweep
    /// Returns all functions found by either method (union of both)
    pub fn find_all_functions(&self) -> Result<Vec<FunctionAnalysis>> {
        let mut all_functions = Vec::new();

        // Get functions from exception directory (if available)
        // let exception_functions = self.find_all_functions_from_exception_directory()?;
        // debug!(
        //     count = exception_functions.len(),
        //     "Functions found via exception directory"
        // );
        // for func in exception_functions {
        //     all_functions.insert((func.start, func.end));
        // }

        // Get functions from linear sweep
        let linear_sweep_functions = self.find_functions_linear_sweep()?;
        debug!(
            count = linear_sweep_functions.len(),
            "Functions found via linear sweep"
        );
        all_functions.extend(linear_sweep_functions);
        // for func in linear_sweep_functions {
        //     all_functions.insert((func.start, func.end));
        // }

        // Convert back to Vec and merge overlapping ranges
        // let mut function_ranges: Vec<FunctionRange> = all_functions
        //     .into_iter()
        //     .map(|(start, end)| FunctionRange { start, end })
        //     .collect();

        all_functions.sort_by_key(|f| f.entry_point);
        // let function_ranges = self.merge_overlapping_ranges(function_ranges);

        tracing::info!(
            final_count = all_functions.len(),
            "All functions discovery complete"
        );

        Ok(all_functions)
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

fn get_branch_target(instruction: &iced_x86::Instruction) -> Option<u64> {
    match instruction.op_kind(0) {
        OpKind::NearBranch16 => Some(instruction.near_branch16() as u64),
        OpKind::NearBranch32 => Some(instruction.near_branch32() as u64),
        OpKind::NearBranch64 => Some(instruction.near_branch64()),
        _ => None,
    }
}

/// Detect and parse jump table targets from indirect jump instructions
fn detect_jump_table_targets(
    instruction: &Instruction,
    pe_loader: &PeLoader,
) -> Option<(JumpTable, Vec<u64>)> {
    // Check if this is an indirect jump with memory operand
    if instruction.mnemonic() != Mnemonic::Jmp || instruction.op_count() == 0 {
        return None;
    }

    // Look for jump table pattern: jmp [index*scale+table_base]
    if instruction.op_kind(0) == OpKind::Memory {
        let memory_base = instruction.memory_base();
        let memory_index = instruction.memory_index();
        let memory_scale = instruction.memory_index_scale();
        let memory_displacement = instruction.memory_displacement64();

        // Pattern: jmp [reg*4+table_address] for PE32
        if pe_loader.bitness() == 32
            && memory_base == Register::None
            && memory_index != Register::None
            && memory_scale == 4
            && memory_displacement != 0
        {
            // This looks like a jump table access
            let table_address = memory_displacement;

            // Try to read the jump table
            if let Ok(targets) = parse_jump_table_at_address(pe_loader, table_address) {
                trace!(
                    instruction_address = format!("0x{:x}", instruction.ip()),
                    table_address = format!("0x{:x}", table_address),
                    targets_found = targets.len(),
                    "Detected jump table"
                );
                return Some((
                    JumpTable {
                        start: table_address,
                        end: table_address + 4 * targets.len() as u64,
                    },
                    targets,
                ));
            }
        }
    }

    None
}

/// Parse a jump table at the given address and return target addresses
fn parse_jump_table_at_address(pe_loader: &PeLoader, table_address: u64) -> Result<Vec<u64>> {
    let mut targets = Vec::new();

    // Check if the table address is within a valid section
    if !pe_loader.is_address_in_section(table_address) {
        return Ok(targets);
    }

    for i in 0.. {
        let entry_address = table_address + i * 4;

        // Try to read the table entry
        let target = {
            match pe_loader.read_at_va(entry_address, 4) {
                Ok(bytes) => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
                Err(_) => break,
            }
        };

        // Validate the target address
        if target == 0 || !pe_loader.is_address_in_section(target) {
            // Likely end of table or invalid entry
            break;
        }

        // Check if target looks like a valid code address
        // by trying to decode an instruction there
        match pe_loader.read_at_va(target, 16) {
            Ok(bytes) => {
                let mut decoder =
                    Decoder::with_ip(pe_loader.bitness(), bytes, target, DecoderOptions::NONE);
                let instruction = decoder.decode();
                if instruction.mnemonic() == Mnemonic::INVALID {
                    // Not valid code, likely end of table
                    break;
                }
                targets.push(target);
            }
            Err(_) => break,
        }
    }

    Ok(targets)
}
