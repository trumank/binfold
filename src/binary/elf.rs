//! ELF-specific loading: eh_frame FDE bounds, dynsym/gnu-hash symbol recovery.

use anyhow::{Result, anyhow, bail};
use object::elf::{PT_GNU_EH_FRAME, PT_LOAD};
use object::read::elf::ProgramHeader;

use super::FunctionRange;

impl super::Binary {
    /// Discover function start/end ranges from DWARF Call Frame Information
    /// in `.eh_frame`.
    ///
    /// We locate `.eh_frame_hdr` via the `PT_GNU_EH_FRAME` program header
    /// (the section header table is often stripped on shipping binaries;
    /// program headers are not), follow its `eh_frame_ptr` to `.eh_frame`,
    /// then walk every FDE. Each FDE yields an `initial_address` and `len`
    /// covering one function; the unwind opcodes themselves are unused.
    pub fn find_all_functions_from_eh_frame(
        &self,
        on_warning: &dyn Fn(&str),
    ) -> Result<Vec<FunctionRange>> {
        use gimli::{
            BaseAddresses, CieOrFde, EhFrame, EhFrameHdr, EndianSlice, LittleEndian, UnwindSection,
        };

        let file = self.file.borrow_dependent();
        let elf = match file {
            object::File::Elf64(e) => e,
            _ => return Ok(vec![]),
        };

        // gimli uses zero-sized endian types; object expects a runtime
        // Endianness value. ELF aarch64 is always little-endian here.
        let endian = LittleEndian;
        let obj_endian = elf.endian();
        let address_size: u8 = 8;
        let file_data = self.file.borrow_owner();

        // Locate the PT_GNU_EH_FRAME program header. `object::segments()`
        // filters to PT_LOAD only, so walk the raw program headers.
        let mut hdr_va: Option<u64> = None;
        let mut hdr_size: Option<u64> = None;
        for ph in elf.elf_program_headers() {
            if ph.p_type(obj_endian) == PT_GNU_EH_FRAME {
                hdr_va = Some(ph.p_vaddr(obj_endian));
                hdr_size = Some(ph.p_filesz(obj_endian));
                break;
            }
        }
        let (Some(hdr_va), Some(hdr_size)) = (hdr_va, hdr_size) else {
            on_warning("ELF has no PT_GNU_EH_FRAME segment; no function seeds");
            return Ok(vec![]);
        };

        let hdr_offset = self.rva_to_file_offset(hdr_va.saturating_sub(self.image_base()))?;
        let hdr_end = hdr_offset
            .checked_add(hdr_size as usize)
            .ok_or_else(|| anyhow!("eh_frame_hdr size overflows file offset"))?;
        let hdr_bytes = file_data
            .get(hdr_offset..hdr_end)
            .ok_or_else(|| anyhow!("eh_frame_hdr out of bounds"))?;

        let bases = BaseAddresses::default().set_eh_frame_hdr(hdr_va);
        let eh_frame_hdr = EhFrameHdr::new(hdr_bytes, endian).parse(&bases, address_size)?;

        // `.eh_frame` itself: take its start from the header pointer and
        // give gimli the entire tail of the containing PT_LOAD segment.
        // The CFI section is self-terminating (a zero-length CIE marks the
        // end), so gimli will stop on its own before the slice ends.
        let eh_frame_va = match eh_frame_hdr.eh_frame_ptr() {
            gimli::Pointer::Direct(p) => p,
            gimli::Pointer::Indirect(p) => p,
        };
        let eh_frame_offset =
            self.rva_to_file_offset(eh_frame_va.saturating_sub(self.image_base()))?;
        let eh_frame_end = elf
            .elf_program_headers()
            .iter()
            .filter(|ph| ph.p_type(obj_endian) == PT_LOAD)
            .filter_map(|ph| {
                let start = ph.p_offset(obj_endian) as usize;
                let end = start + ph.p_filesz(obj_endian) as usize;
                (start <= eh_frame_offset && eh_frame_offset < end).then_some(end)
            })
            .next()
            .unwrap_or(file_data.len());
        if eh_frame_offset > eh_frame_end {
            bail!("eh_frame range is reversed");
        }
        let eh_frame_bytes = file_data
            .get(eh_frame_offset..eh_frame_end)
            .ok_or_else(|| anyhow!("eh_frame out of bounds"))?;

        let bases = bases.set_eh_frame(eh_frame_va);
        let eh_frame: EhFrame<EndianSlice<LittleEndian>> = EhFrame::new(eh_frame_bytes, endian);

        let mut ranges = Vec::new();
        let mut entries = eh_frame.entries(&bases);
        loop {
            match entries.next() {
                Ok(None) => break,
                Ok(Some(CieOrFde::Cie(_))) => {}
                Ok(Some(CieOrFde::Fde(partial))) => match partial.parse(EhFrame::cie_from_offset) {
                    Ok(fde) => {
                        let start = fde.initial_address();
                        let len = fde.len();
                        if len > 0 {
                            ranges.push(FunctionRange {
                                start,
                                end: start + len,
                            });
                        }
                    }
                    Err(e) => {
                        on_warning(&format!("eh_frame: bad FDE: {e}"));
                    }
                },
                Err(e) => {
                    on_warning(&format!("eh_frame: walk aborted: {e}"));
                    break;
                }
            }
        }

        ranges.sort_by_key(|r| r.start);
        ranges.dedup_by_key(|r| r.start);
        Ok(ranges)
    }
}
