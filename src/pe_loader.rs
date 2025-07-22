use memmap2::Mmap;
use object::pe::ImageNtHeaders64;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};
use std::fs::File;
use std::path::Path;

pub struct PeLoader {
    mmap: Mmap,
    image_base: u64,
}

impl PeLoader {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
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
    pub fn rva_to_file_offset(&self, rva: u64) -> Result<usize, Box<dyn std::error::Error>> {
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

        Err(format!("RVA 0x{:x} not found in any section", rva).into())
    }

    /// Read bytes at a given virtual address
    pub fn read_at_va(&self, va: u64, size: usize) -> Result<&[u8], Box<dyn std::error::Error>> {
        // Convert VA to RVA
        let rva = va.saturating_sub(self.image_base);
        let file_offset = self.rva_to_file_offset(rva)?;

        // Bounds check
        if file_offset + size > self.mmap.len() {
            return Err("Read would go past end of file".into());
        }

        Ok(&self.mmap[file_offset..file_offset + size])
    }

    /// Find a function at the given address and return its approximate size
    /// This is a heuristic - it looks for RET instructions or the next function
    pub fn find_function_size(&self, va: u64) -> Result<usize, Box<dyn std::error::Error>> {
        use iced_x86::{Decoder, DecoderOptions, FlowControl};

        let max_scan = 0x1000; // Maximum function size to scan (4KB)
        let start_offset = self.rva_to_file_offset(va.saturating_sub(self.image_base))?;

        // Adjust max_scan if it would go past end of file
        let available = self.mmap.len().saturating_sub(start_offset);
        let scan_size = max_scan.min(available);

        if scan_size == 0 {
            return Err("No bytes available to scan".into());
        }

        let bytes = &self.mmap[start_offset..start_offset + scan_size];
        let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);

        let mut size = 0;
        let mut found_ret = false;

        while decoder.can_decode() && !found_ret {
            let instruction = decoder.decode();
            let instr_end = (decoder.ip() - va) as usize;

            match instruction.flow_control() {
                FlowControl::Return => {
                    size = instr_end;
                    found_ret = true;
                }
                FlowControl::UnconditionalBranch => {
                    // Check if it's a tail call (jmp to external function)
                    if let Some(target) = get_branch_target(&instruction) {
                        if target < self.image_base || target > self.image_base + 0x10000000 {
                            // Likely a tail call
                            size = instr_end;
                            found_ret = true;
                        }
                    }
                }
                _ => {}
            }

            // Update size even if we haven't found ret yet
            if !found_ret {
                size = instr_end;
            }
        }

        if size == 0 {
            return Err("Could not determine function size".into());
        }

        Ok(size)
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
