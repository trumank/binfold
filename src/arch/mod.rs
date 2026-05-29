//! Per-architecture analysis backends.
//!
//! Each backend implements the recursive-descent function analyzer and the
//! WARP per-block byte emitter. The format-level loader and the
//! GUID/constraint logic in `warp` are arch-agnostic and dispatch here.
//!
//! This module is also the home of the arch-neutral analysis contract: the
//! types describing a function's analysis result (`FunctionAnalysis`,
//! `FunctionCall`, `DataReference`, `BlockBound`), the `Arch` enum, and the
//! `MemoryView` trait abstracting read access to a loaded image.

use std::collections::BTreeMap;
use std::ops::Range;

use anyhow::Result;

pub mod arm64;
pub mod x86;

/// Per-architecture WARP byte masker.
///
/// Produces the WARP bytes for one basic block: the raw instruction bytes
/// with relocatable / address-bearing instruction fields zeroed. The hashing
/// itself lives in `warp`; this trait only decides which bytes survive.
pub trait BlockMasker {
    /// `va` is the block start VA, `bounds` the function's [start, end) VA
    /// range. May be stateful across the blocks of one function (e.g. arm64
    /// ADRP taint), so construct fresh per function.
    fn mask(&mut self, raw: &[u8], va: u64, bounds: Range<u64>) -> Vec<u8>;
}

/// Target instruction-set architecture supported by the loader.
///
/// `bitness` on `Arch::X86_64` is what the iced-x86 decoder consumes; the
/// arm64 path uses its own (fixed-4-byte) decoder and does not go through
/// iced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
    Aarch64,
}

impl Arch {
    /// The recursive-descent analyzer backend for this architecture.
    pub fn isa(self) -> &'static dyn InstructionSet {
        match self {
            Arch::Aarch64 => &arm64::Arm64Isa,
            _ => &x86::X86Isa,
        }
    }

    /// Pointer/decoder bitness for this architecture. For x86 this is what the
    /// iced-x86 decoder consumes; arm64 is fixed-width 64-bit.
    pub fn bitness(self) -> u32 {
        match self {
            Arch::X86 => 32,
            Arch::X86_64 => 64,
            Arch::Aarch64 => 64,
        }
    }
}

/// Per-architecture recursive-descent function analyzer. Walks reachable
/// instructions from a function entry point, recording basic-block bounds,
/// direct calls, and data references into a [`FunctionAnalysis`]. The result
/// is arch-neutral; only the decode/flow logic differs per backend.
pub trait InstructionSet: Sync {
    fn analyze_function(&self, mem: &dyn MemoryView, va: u64) -> Result<FunctionAnalysis>;
}

#[derive(Debug, Clone)]
pub struct FunctionCall {
    /// instruction address of CALL
    pub address: u64,
    /// CALL target address
    pub target: u64,
}

/// A jump table located during analysis: a contiguous run of code-address
/// entries that an indirect `jmp` dispatches through. Recorded so the linear
/// sweep can carve the table *data* out of the code interval map. Only the
/// PE32 x86 backend populates these today; the field is empty everywhere else.
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// start address of the jump table
    pub start: u64,
    /// end address of the jump table (exclusive)
    pub end: u64,
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

/// Control flow graph built during recursive descent
#[derive(Debug, Default, Clone)]
pub struct FunctionAnalysis {
    pub size: usize,
    /// Block bounds start -> end
    pub basic_blocks: BTreeMap<u64, u64>,
    pub entry_point: u64,
    pub calls: Vec<FunctionCall>,
    pub data_refs: Vec<DataReference>,
    /// Jump tables discovered while walking the function. Populated only by the
    /// PE32 backend (see [`JumpTable`]); empty for x86-64, ELF-i386, and arm64.
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

/// Arch-neutral read access to a loaded image. Mirrors the inherent accessor
/// methods on `Binary` so analysis code can be generic over the loader.
pub trait MemoryView {
    fn arch(&self) -> Result<Arch>;
    fn image_base(&self) -> u64;
    fn read_at_va(&self, va: u64, size: usize) -> Result<&[u8]>;
    fn is_address_writable(&self, va: u64) -> Result<bool>;

    /// Operand bitness of the target decoder (16/32/64). The x86 backend
    /// feeds this to iced-x86; arm64 reports 64 but decodes on its own and
    /// never reads it. Required (not defaulted) so no loader can silently
    /// fall back to a wrong width.
    fn bitness(&self) -> u32;

    /// The raw bytes of the loaded image as mapped from disk.
    fn raw_bytes(&self) -> &[u8];

    /// Convert an RVA to a file offset into [`raw_bytes`].
    fn rva_to_file_offset(&self, rva: u64) -> Result<usize>;

    /// Optional `[start, end)` size hint for the function at `va`, sourced
    /// from unwind metadata when the loader has it (ELF `.eh_frame` FDEs
    /// today). The arm64 walk treats it as a hard scan cap; the x86 walk
    /// ignores it. Defaults to `None` for loaders without such metadata.
    fn function_size_hint(&self, _va: u64) -> Option<u64> {
        None
    }

    /// True if `va` is a known function-start address (e.g. an `.eh_frame`
    /// FDE `initial_address`). The arm64 walk uses this to reject FDE-less
    /// tail-call over-scans into a neighbour. Defaults to `false` for
    /// loaders without function-boundary metadata.
    fn is_known_function_start(&self, _va: u64) -> bool {
        false
    }

    /// True if `va` falls within any mapped section/segment of the image.
    /// The PE32 backend uses this to decide whether an immediate or memory
    /// displacement is a relocated section address (mask it) versus a plain
    /// constant, and to validate jump-table entries. Defaults to `false` for
    /// backends that don't need it.
    fn is_address_in_section(&self, _va: u64) -> bool {
        false
    }

    /// True for PE images. Gates PE32-only analysis (absolute-address masking,
    /// jump-table recovery) so x86-64, ELF-i386, and arm64 paths are untouched.
    fn is_pe(&self) -> bool {
        false
    }
}
