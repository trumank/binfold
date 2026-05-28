//! PE/COFF-specific loading: exception directory, IAT/imports, PDB debug info.

use anyhow::{Context, Result, bail};
use object::LittleEndian as LE;
use object::pe::{IMAGE_DIRECTORY_ENTRY_EXCEPTION, ImageNtHeaders64};
use object::read::pe::{ImageNtHeaders, Import, PeFile64};
use std::collections::{HashMap, HashSet};
use std::ops::Range;

use super::FunctionRange;

#[derive(Debug, Clone)]
pub struct RuntimeFunction {
    pub range: Range<usize>,
    pub unwind: usize,
}

#[derive(Debug)]
pub struct PdbDebugInfo {
    pub guid: [u8; 16],
    pub age: u32,
    pub pdb_path: String,
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

impl super::Binary {
    /// Get the exception directory range (PE-only).
    pub fn get_exception_directory_range(&self) -> Result<Option<Range<usize>>> {
        let file = self.file.borrow_dependent();
        let Some(exception_directory) = (match file {
            object::File::Pe32(pe_file) => pe_file.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION),
            object::File::Pe64(pe_file) => pe_file.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION),
            _ => return Ok(None),
        }) else {
            return Ok(None);
        };

        let (address, size) = exception_directory.address_range();
        let start_offset = self.rva_to_file_offset(address as u64)?;
        let end_offset = start_offset + size as usize;

        Ok(Some(start_offset..end_offset))
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
    pub fn find_all_functions_from_exception_directory(
        &self,
        on_warning: &dyn Fn(&str),
    ) -> Result<Vec<FunctionRange>> {
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
            let unwind_offset = match self
                .rva_to_file_offset((func.unwind as u64).saturating_sub(self.image_base()))
            {
                Ok(unwind_offset) => unwind_offset,
                Err(e) => {
                    on_warning(&format!("{e}: {func:x?}"));
                    continue;
                }
            };
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

    /// Get the PE section table. Errors on non-PE images, so callers must
    /// gate on [`super::Binary::is_pe`] (the PDB writer is the only caller
    /// and is PE-only by construction).
    pub fn sections(&self) -> Result<Vec<SectionInfo>> {
        let file = self.file.borrow_dependent();

        let table = match file {
            object::File::Pe32(pe_file) => pe_file.section_table(),
            object::File::Pe64(pe_file) => pe_file.section_table(),
            _ => bail!("Only PE32/PE64 files are supported"),
        };

        Ok(table
            .iter()
            .map(|section: &object::pe::ImageSectionHeader| SectionInfo {
                name_bytes: section.name,
                virtual_address: section.virtual_address.get(LE),
                virtual_size: section.virtual_size.get(LE),
                size_of_raw_data: section.size_of_raw_data.get(LE),
                pointer_to_raw_data: section.pointer_to_raw_data.get(LE),
                characteristics: section.characteristics.get(LE),
            })
            .collect())
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
                let offset = self.rva_to_file_offset(entry.address_of_raw_data.get(LE) as u64)?;

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

                // Parse PDB path (null-terminated string starting at offset 24)
                let pdb_path_bytes = &debug_data[24..];
                let pdb_path_end = pdb_path_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(pdb_path_bytes.len());
                let pdb_path =
                    String::from_utf8_lossy(&pdb_path_bytes[..pdb_path_end]).into_owned();

                return Ok(PdbDebugInfo {
                    guid,
                    age,
                    pdb_path,
                });
            }
        }

        bail!("No CodeView debug info found")
    }

    /// Parse the PE import table into `iat_slot_va -> api_name`. The VA
    /// points at the *runtime* IAT slot (FirstThunk), which is what a
    /// `call [rip+X]` or `jmp [rip+X]` through that import resolves to.
    ///
    /// Only supports PE64 today; PE32 returns an empty map.
    pub fn iat(&self) -> Result<HashMap<u64, String>> {
        let mut iat: HashMap<u64, String> = HashMap::new();

        let file_data = self.file.borrow_owner();
        let Ok(pe) = PeFile64::parse(&file_data[..]) else {
            return Ok(iat);
        };
        let Some(table) = pe.import_table()? else {
            return Ok(iat);
        };

        let image_base = self.image_base();
        // PE64 thunk entries are 8 bytes (IMAGE_THUNK_DATA64 is a u64).
        const THUNK_SIZE: u32 = 8;

        let mut descs = table.descriptors()?;
        while let Some(desc) = descs.next()? {
            // Prefer OriginalFirstThunk (the name-table, never patched at
            // runtime); fall back to FirstThunk when OFT isn't set.
            let oft = desc.original_first_thunk.get(LE);
            let ft = desc.first_thunk.get(LE);
            let name_rva = if oft != 0 { oft } else { ft };

            let mut thunks = table.thunks(name_rva)?;
            let mut slot_rva = ft;
            while let Some(thunk) = thunks.next::<ImageNtHeaders64>()? {
                let name = match table.import::<ImageNtHeaders64>(thunk)? {
                    Import::Ordinal(n) => format!("ord_{}", n),
                    Import::Name(_hint, bytes) => String::from_utf8_lossy(bytes).into_owned(),
                };
                iat.insert(image_base + slot_rva as u64, name);
                slot_rva += THUNK_SIZE;
            }
        }
        Ok(iat)
    }

    /// If the function at `va` is a 6-byte import thunk of the shape
    /// `jmp [rip+disp32]` whose target is a slot in `iat`, return the
    /// imported API name.
    pub fn thunk_import(&self, va: u64, iat: &HashMap<u64, String>) -> Option<String> {
        let bytes = self.read_at_va(va, 6).ok()?;
        // Opcode FF 25 is `jmp qword ptr [rip+disp32]`.
        if bytes[0] != 0xff || bytes[1] != 0x25 {
            return None;
        }
        let disp = i32::from_le_bytes(bytes[2..6].try_into().ok()?) as i64;
        let target = va.wrapping_add(6).wrapping_add(disp as u64);
        iat.get(&target).cloned()
    }
}
