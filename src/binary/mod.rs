use anyhow::{Result, anyhow, bail};
use dashmap::DashMap;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use memmap2::Mmap;
use object::{Architecture, File, Object, ObjectSegment, SegmentFlags};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::{self};
use std::path::Path;
use std::sync::Arc;

// PE section characteristics (memory protection bits).
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
// ELF program-header protection flags.
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;

pub use crate::arch::{
    Arch, BlockBound, DataReference, FunctionAnalysis, FunctionCall, MemoryView,
};

mod elf;
mod pe;

// PE-only types live in `pe.rs`; re-exported here so the public API path
// (`crate::binary::...`) is unchanged for the PE-specific callers.
pub use pe::{PdbDebugInfo, RuntimeFunction, SectionInfo};

#[derive(Debug, Clone)]
pub struct FunctionRange {
    pub start: u64,
    pub end: u64,
}

/// A loaded segment (PE section / ELF `PT_LOAD`) with its decoded R/W/X
/// protection bits. Format-neutral so callers don't re-decode
/// `SegmentFlags::{Coff,Elf}` or re-hardcode the protection constants.
#[derive(Debug, Clone, Copy)]
pub struct SegmentPerms {
    pub va: u64,
    pub size: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
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
    cache: DashMap<u64, Result<Arc<FunctionAnalysis>>>,
}
impl AnalysisCache {
    pub fn new(functions: impl IntoIterator<Item = FunctionAnalysis>) -> Self {
        Self {
            cache: functions
                .into_iter()
                .map(|func| (func.entry_point, Ok(Arc::new(func))))
                .collect(),
        }
    }
    pub fn get(&self, address: u64, bin: &Binary) -> Result<Arc<FunctionAnalysis>> {
        fn map(res: &Result<Arc<FunctionAnalysis>>) -> Result<Arc<FunctionAnalysis>> {
            res.as_ref()
                .map(|v| v.clone())
                .map_err(|e| anyhow!("cache: {e:?}"))
        }

        if let Some(res) = self.cache.get(&address) {
            return map(res.value());
        }

        // Compute outside any shard lock so other threads aren't blocked on
        // analyze_function. Concurrent first-callers may duplicate the work,
        // but the result is the same and the dup is rare on a hot cache.
        let result = bin.analyze_function(address).map(Arc::new);

        map(self.cache.entry(address).or_insert(result).value())
    }
}

pub struct Binary {
    file: FileData,
    /// `start_va -> end_va` hints for known function bounds. On ELF this is
    /// built from `.eh_frame` FDEs; on PE it could be built from the
    /// exception directory. Populated lazily by `fde_bounds()` so analyzers
    /// can clamp recursive descent and not over-shoot the real function end
    /// (e.g. through `BL` to a `noreturn` like `__stack_chk_fail`).
    fde_bounds: std::sync::OnceLock<HashMap<u64, u64>>,
}

/// Why [`Binary::load`] rejected a file. Lets callers that sweep many files
/// (e.g. gen-db over a directory tree) distinguish "this isn't a binary"
/// (ignorable) from "this is a binary I can't use" (worth reporting) without
/// re-inspecting the file.
#[derive(Debug)]
pub enum LoadError {
    /// The path could not be opened or memory-mapped.
    Io(std::io::Error),
    /// No recognized object-file magic; not a binary at all.
    NotObject,
    /// Recognized as an object file but failed to parse.
    Parse(object::Error),
    /// A well-formed object file, but for an architecture we don't support.
    UnsupportedArch(Architecture),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "{e}"),
            LoadError::NotObject => write!(f, "not an object file"),
            LoadError::Parse(e) => write!(f, "{e}"),
            LoadError::UnsupportedArch(a) => write!(f, "Unsupported architecture: {a:?}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl Binary {
    pub fn load<P: AsRef<Path>>(path: P) -> std::result::Result<Self, LoadError> {
        let file = fs::File::open(path).map_err(LoadError::Io)?;
        let mmap = unsafe { Mmap::map(&file) }.map_err(LoadError::Io)?;

        // Classify "not a binary" distinctly from a parse failure on a real
        // object, so directory sweeps can ignore the former and report the
        // latter.
        if object::FileKind::parse(&mmap[..]).is_err() {
            return Err(LoadError::NotObject);
        }

        let loader = Self {
            file: FileData::try_new(mmap, |mmap| object::File::parse(mmap))
                .map_err(LoadError::Parse)?,
            fde_bounds: std::sync::OnceLock::new(),
        };
        // Surface unsupported architectures up front rather than letting them
        // bomb out deep in the decode path. `arch()` is the single source of
        // truth for the supported set; report the raw architecture on rejection.
        if loader.arch().is_err() {
            return Err(LoadError::UnsupportedArch(
                loader.file.borrow_dependent().architecture(),
            ));
        }
        Ok(loader)
    }

    /// `start_va -> end_va` hints for known function bounds, lazily computed
    /// from `.eh_frame` FDEs (so the gate is `!is_pe()`, not a specific arch).
    /// Both the arm64 and x86 `analyze_function` paths clamp their scan window
    /// to the matching end when a hint is present, and treat a branch onto a
    /// known start as a tail call. Empty on PE or when `.eh_frame` is missing,
    /// in which case the analyzers fall back to their distance heuristics.
    pub fn fde_bounds(&self) -> &HashMap<u64, u64> {
        self.fde_bounds.get_or_init(|| {
            let mut map = HashMap::new();
            // `.eh_frame` is an ELF feature; PE could populate this from the
            // exception directory if we wanted similar bounds protection.
            if !self.is_pe()
                && let Ok(ranges) = self.find_all_functions_from_eh_frame(&|_| {})
            {
                for r in ranges {
                    map.insert(r.start, r.end);
                }
            }
            map
        })
    }

    /// The raw bytes of the loaded binary as mapped from disk.
    pub fn raw_bytes(&self) -> &[u8] {
        self.file.borrow_owner()
    }

    /// The parsed `object::File` view of the loaded image. Format-specific
    /// readers (symbol tables, etc.) borrow this rather than re-parsing the
    /// mmap.
    pub fn object_file(&self) -> &object::File<'_> {
        self.file.borrow_dependent()
    }

    pub fn image_base(&self) -> u64 {
        self.file.borrow_dependent().relative_address_base()
    }

    /// Target architecture of the loaded binary.
    pub fn arch(&self) -> Result<Arch> {
        let file = self.file.borrow_dependent();
        Ok(match (file.architecture(), file) {
            (Architecture::X86_64, _) => Arch::X86_64,
            (Architecture::I386, _) => Arch::X86,
            (Architecture::Aarch64, _) => Arch::Aarch64,
            (other, _) => bail!("Unsupported architecture: {:?}", other),
        })
    }

    /// True if the binary is a PE/COFF (Windows) image.
    pub fn is_pe(&self) -> bool {
        matches!(
            self.file.borrow_dependent(),
            object::File::Pe32(_) | object::File::Pe64(_)
        )
    }

    /// Bitness as understood by the iced-x86 decoder (32 or 64). Drives the
    /// x86 decoder/masker; arm64 reports 64 and uses its own decoder. Derived
    /// from `arch()`, which `load()` already validated.
    pub fn bitness(&self) -> u32 {
        self.arch()
            .expect("arch validated in Binary::load")
            .bitness()
    }

    /// Convert RVA to file offset.
    ///
    /// Uses program segments (PE sections are also segments in the `object`
    /// model; ELF segments are PT_LOAD entries). This works on stripped ELF
    /// shared objects that have no section header table.
    pub fn rva_to_file_offset(&self, rva: u64) -> Result<usize> {
        let file = self.file.borrow_dependent();
        let image_base = self.image_base();

        for seg in file.segments() {
            let seg_rva = seg.address().saturating_sub(image_base);
            let (file_offset, file_size) = seg.file_range();
            // Only the on-disk portion of the segment is addressable via a
            // file offset (BSS-like memory-only tails have no backing bytes).
            if rva >= seg_rva && rva < seg_rva + file_size {
                return Ok((file_offset + (rva - seg_rva)) as usize);
            }
        }

        bail!("RVA 0x{:x} not found in any loaded segment", rva)
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

    /// Analyze the function at `va` via the architecture's recursive-descent
    /// backend. Dispatches through [`Arch::isa`]; `self` coerces to a
    /// `&dyn MemoryView` so each backend reads the image format-neutrally.
    pub fn analyze_function(&self, va: u64) -> Result<FunctionAnalysis> {
        self.arch()?.isa().analyze_function(self, va)
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

    /// Enumerate every loaded segment (PE section / ELF `PT_LOAD`) with its
    /// decoded R/W/X protection bits.
    ///
    /// Drives off the format-neutral `ObjectSegment::flags()` enum, so the
    /// same iterator works for PE section characteristics and ELF
    /// program-header `p_flags`. This is the one place the protection-bit
    /// encodings are read; callers consume the decoded [`SegmentPerms`].
    pub fn segments_with_perms(&self) -> impl Iterator<Item = SegmentPerms> + '_ {
        self.file.borrow_dependent().segments().map(|seg| {
            let (read, write, execute) = match seg.flags() {
                SegmentFlags::Coff { characteristics } => (
                    (characteristics & IMAGE_SCN_MEM_READ) != 0,
                    (characteristics & IMAGE_SCN_MEM_WRITE) != 0,
                    (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0,
                ),
                SegmentFlags::Elf { p_flags } => (
                    (p_flags & PF_R) != 0,
                    (p_flags & PF_W) != 0,
                    (p_flags & PF_X) != 0,
                ),
                _ => (false, false, false),
            };
            SegmentPerms {
                va: seg.address(),
                size: seg.size(),
                read,
                write,
                execute,
            }
        })
    }

    /// The GNU build-id (ELF) / equivalent unique image id, if present.
    /// Borrows the `object::File` the loader already owns rather than
    /// re-parsing the mmap.
    pub fn build_id(&self) -> Option<&[u8]> {
        self.file.borrow_dependent().build_id().ok().flatten()
    }

    /// Check if a virtual address is in a writable segment.
    pub fn is_address_writable(&self, va: u64) -> Result<bool> {
        Ok(self
            .segments_with_perms()
            .find(|s| va >= s.va && va < s.va + s.size)
            .is_some_and(|s| s.write))
    }

    pub fn find_all_functions(&self, on_warning: &dyn Fn(&str)) -> Result<Vec<FunctionAnalysis>> {
        // Seed discovery from a format-appropriate source. On PE that's the
        // exception directory; on ELF (Linux/Android) it's the DWARF CFI in
        // `.eh_frame` (which the platform unwinder also relies on, so it's
        // present in stripped shipping binaries too). Recursive expansion
        // below follows direct calls past whatever the seed set misses.
        let runtime_functions = if self.is_pe() {
            self.find_all_functions_from_exception_directory(on_warning)?
        } else {
            self.find_all_functions_from_eh_frame(on_warning)
                .unwrap_or_else(|e| {
                    on_warning(&format!(".eh_frame discovery failed: {e}"));
                    Vec::new()
                })
        };

        let mut visited: HashSet<u64> = Default::default();
        let mut result = vec![];

        let mut current_batch: Vec<u64> = {
            runtime_functions
                .into_iter()
                .map(|f| f.start)
                .filter(|addr| visited.insert(*addr))
                .collect()
        };

        while !current_batch.is_empty() {
            let batch_output: Vec<_> = current_batch
                .par_iter()
                .filter_map(|&addr| match self.analyze_function(addr) {
                    Ok(analysis) => {
                        let targets: Vec<u64> = analysis.calls.iter().map(|c| c.target).collect();
                        Some((analysis, targets))
                    }
                    Err(e) => {
                        tracing::info!(
                            address = format!("0x{addr:x}"),
                            error = %e,
                            "Failed to analyze function"
                        );
                        None
                    }
                })
                .collect();

            let mut next_batch = Vec::new();
            for (analysis, targets) in batch_output {
                result.push(analysis);
                for target in targets {
                    if visited.insert(target) {
                        next_batch.push(target);
                    }
                }
            }

            current_batch = next_batch;
        }

        Ok(result)
    }
}

/// A directed CFG edge between two basic-block start addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CfgEdge {
    pub from: u64,
    pub to: u64,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Fall-through to the instruction after a non-branch / conditional-branch / call terminator.
    Fallthrough,
    /// Taken edge of a conditional or unconditional branch.
    Taken,
}

impl MemoryView for Binary {
    fn arch(&self) -> Result<Arch> {
        self.arch()
    }

    fn image_base(&self) -> u64 {
        self.image_base()
    }

    fn read_at_va(&self, va: u64, size: usize) -> Result<&[u8]> {
        self.read_at_va(va, size)
    }

    fn is_address_writable(&self, va: u64) -> Result<bool> {
        self.is_address_writable(va)
    }

    fn bitness(&self) -> u32 {
        self.bitness()
    }

    fn raw_bytes(&self) -> &[u8] {
        self.raw_bytes()
    }

    fn rva_to_file_offset(&self, rva: u64) -> Result<usize> {
        self.rva_to_file_offset(rva)
    }

    fn function_size_hint(&self, va: u64) -> Option<u64> {
        self.fde_bounds().get(&va).copied()
    }

    fn is_known_function_start(&self, va: u64) -> bool {
        self.fde_bounds().contains_key(&va)
    }
}

impl FunctionAnalysis {
    /// Decode each basic block's terminator and enumerate CFG edges to
    /// other blocks in the same function. Indirect branches contribute no
    /// edges (target unknown); returns land with no edges either.
    pub fn cfg_edges(&self, bin: &Binary) -> Result<Vec<CfgEdge>> {
        let base = self.entry_point;
        let bytes = bin.read_at_va(base, self.size)?;

        let mut edges = Vec::new();
        for (&start, &end) in &self.basic_blocks {
            let off = (start - base) as usize;
            let end_off = (end - base) as usize;
            if end_off > bytes.len() {
                continue;
            }
            let slice = &bytes[off..end_off];
            let mut decoder = Decoder::with_ip(bin.bitness(), slice, start, DecoderOptions::NONE);
            let mut last: Option<Instruction> = None;
            while decoder.can_decode() {
                last = Some(decoder.decode());
            }
            let Some(insn) = last else { continue };
            let fall = end;
            let taken = crate::arch::x86::get_branch_target(&insn);

            match insn.flow_control() {
                FlowControl::UnconditionalBranch => {
                    if let Some(t) = taken
                        && self.basic_blocks.contains_key(&t)
                    {
                        edges.push(CfgEdge {
                            from: start,
                            to: t,
                            kind: EdgeKind::Taken,
                        });
                    }
                }
                FlowControl::ConditionalBranch => {
                    if let Some(t) = taken
                        && self.basic_blocks.contains_key(&t)
                    {
                        edges.push(CfgEdge {
                            from: start,
                            to: t,
                            kind: EdgeKind::Taken,
                        });
                    }
                    if self.basic_blocks.contains_key(&fall) {
                        edges.push(CfgEdge {
                            from: start,
                            to: fall,
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                }
                // Return / IndirectBranch / Exception (int3, ud2, ...) don't
                // fall through; their successors are unreachable from this
                // block and contribute no edges.
                FlowControl::Return | FlowControl::IndirectBranch | FlowControl::Exception => {}
                // Next / Call / IndirectCall / XbeginXabortXend: control reaches
                // the next instruction in the block (calls return; xbegin
                // continues into the transactional region).
                _ => {
                    if self.basic_blocks.contains_key(&fall) {
                        edges.push(CfgEdge {
                            from: start,
                            to: fall,
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                }
            }
        }
        Ok(edges)
    }

    /// Count back-edges (edge `(u, v)` where `v` is an ancestor of `u` in
    /// the DFS tree rooted at the function's entry point). This is the
    /// standard "loops in the CFG" metric.
    pub fn count_back_edges(&self, edges: &[CfgEdge]) -> usize {
        let mut adj: HashMap<u64, Vec<u64>> = HashMap::new();
        for e in edges {
            adj.entry(e.from).or_default().push(e.to);
        }
        let mut back = 0usize;
        let mut color: HashMap<u64, u8> = HashMap::new(); // 0 white 1 gray 2 black
        let mut stack: Vec<(u64, usize)> = vec![(self.entry_point, 0)];
        color.insert(self.entry_point, 1);
        while let Some(&(node, idx)) = stack.last() {
            let next = adj.get(&node).and_then(|v| v.get(idx)).copied();
            match next {
                Some(child) => {
                    stack.last_mut().unwrap().1 += 1;
                    match color.get(&child).copied().unwrap_or(0) {
                        0 => {
                            color.insert(child, 1);
                            stack.push((child, 0));
                        }
                        1 => back += 1,
                        _ => {}
                    }
                }
                None => {
                    color.insert(node, 2);
                    stack.pop();
                }
            }
        }
        back
    }
}
