//! aarch64 (A64) recursive-descent analyzer and WARP byte emitter.
//!
//! All A64 instructions are 4 bytes wide, so there is no variable-length
//! decode bookkeeping like the x86 path. Each word is decoded with disarm64
//! and dispatched on its instruction class (`Operation::*`).
//!
//! Masking: any instruction encoding a PC-relative immediate must be zeroed
//! so GUIDs stay position-independent:
//!   * `BL imm26`: always (direct call)
//!   * `B imm26`: only when the target leaves the function (tail call)
//!   * `B.cond imm19`, `CBZ/CBNZ imm19`, `TBZ/TBNZ imm14`: same rule
//!   * `ADRP/ADR` (PCRELADDR): always
//!   * `LDR (literal)` (LOADLIT): always
//!
//! Data references via `ADRP`+(`ADD`|`LDR`|`STR`) pairs, plus `ADR` and
//! `LDR (literal)`, are recovered in [`detect_data_ref`]; the masker zeroes
//! the matching `lo12` immediates (see [`mask_lo12_pair`]).

use crate::arch::{
    BlockBound, DataReference, FunctionAnalysis, FunctionCall, InstructionSet, MemoryView,
};
use anyhow::{Result, bail};
use disarm64::decoder;
use disarm64::decoder_full::{Mnemonic, Opcode, Operation};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::Range;
use tracing::{debug, trace};

/// Canonical NOP encoding (`hint #0`). Skipped during WARP byte emission so
/// padding doesn't perturb block hashes.
pub const NOP_BITS: u32 = 0xD503_201F;

/// Classified flow control for an A64 instruction. Mirrors the subset of
/// `iced_x86::FlowControl` the analyzer actually branches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// Falls through to the next instruction.
    Next,
    /// Direct call (BL imm26). Target known; control returns.
    Call { target: u64 },
    /// Indirect call (BLR / BLRAA/BLRAB). Control returns.
    IndirectCall,
    /// Direct unconditional branch (B imm26).
    UncondBranch { target: u64 },
    /// Direct conditional branch (B.cond / CBZ / CBNZ / TBZ / TBNZ).
    /// Both edges live (taken to `target`, fall-through to next).
    CondBranch { target: u64 },
    /// Indirect branch (BR / BRAA/BRAB). Target unknowable statically.
    IndirectBranch,
    /// Return-class (RET / ERET / DRPS).
    Return,
    /// Trap (SVC / HLT / BRK / HVC / SMC / DCPS*). Path ends.
    Exception,
}

/// Decode the 4-byte word at `ip` into `(raw_bits, opcode, flow)`.
/// Returns `None` if disarm64 can't decode the bits (caller treats this as
/// an opaque "next" instruction so we don't drop the entire function on a
/// single unrecognised encoding).
fn decode_op(bytes: &[u8], offset: usize, ip: u64) -> Option<(u32, Opcode, Flow)> {
    let raw = bytes.get(offset..offset + 4)?;
    let bits = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let opcode = decoder::decode(bits)?;
    let flow = classify_flow(&opcode, bits, ip);
    Some((bits, opcode, flow))
}

/// Map a decoded `Opcode` to a `Flow` summary plus computed branch targets.
/// Anything outside the call/branch/return/exception families is `Flow::Next`.
fn classify_flow(op: &Opcode, bits: u32, ip: u64) -> Flow {
    match &op.operation {
        Operation::BRANCH_IMM(_) => {
            // BL (Mnemonic::bl) is the call form; B is the unconditional
            // branch. Both share `imm26`.
            let target = branch_target_imm26(bits, ip);
            match op.mnemonic {
                Mnemonic::bl => Flow::Call { target },
                _ => Flow::UncondBranch { target },
            }
        }
        Operation::BRANCH_REG(_) => match op.mnemonic {
            Mnemonic::blr
            | Mnemonic::blraa
            | Mnemonic::blraaz
            | Mnemonic::blrab
            | Mnemonic::blrabz => Flow::IndirectCall,
            Mnemonic::ret
            | Mnemonic::retaa
            | Mnemonic::retab
            | Mnemonic::eret
            | Mnemonic::eretaa
            | Mnemonic::eretab
            | Mnemonic::drps => Flow::Return,
            _ => Flow::IndirectBranch, // BR / BRAA / BRAAZ / BRAB / BRABZ
        },
        Operation::COMPBRANCH(_) => Flow::CondBranch {
            target: branch_target_imm19(bits, ip),
        },
        Operation::CONDBRANCH(_) => Flow::CondBranch {
            target: branch_target_imm19(bits, ip),
        },
        Operation::TESTBRANCH(_) => Flow::CondBranch {
            target: branch_target_imm14(bits, ip),
        },
        Operation::EXCEPTION(_) => Flow::Exception,
        _ => Flow::Next,
    }
}

/// Decode a `BL`/`B` PC-relative target. `imm26` lives in bits [25:0],
/// is sign-extended, left-shifted by 2, then added to `ip`.
pub fn branch_target_imm26(bits: u32, ip: u64) -> u64 {
    let imm26 = (bits & 0x03FF_FFFF) as i32;
    // sign-extend 26 -> 32
    let signed = (imm26 << 6) >> 6;
    ip.wrapping_add(((signed as i64) << 2) as u64)
}

/// Decode an `imm19` PC-relative target (`B.cond` / `CBZ` / `CBNZ` /
/// `LDR (literal)`). Bits [23:5], sign-extended, shifted left 2.
pub fn branch_target_imm19(bits: u32, ip: u64) -> u64 {
    let imm19 = ((bits >> 5) & 0x7_FFFF) as i32;
    // sign-extend 19 -> 32
    let signed = (imm19 << 13) >> 13;
    ip.wrapping_add(((signed as i64) << 2) as u64)
}

/// Decode a `TBZ` / `TBNZ` `imm14` target. Bits [18:5], sign-extended,
/// shifted left 2.
pub fn branch_target_imm14(bits: u32, ip: u64) -> u64 {
    let imm14 = ((bits >> 5) & 0x3FFF) as i32;
    // sign-extend 14 -> 32
    let signed = (imm14 << 18) >> 18;
    ip.wrapping_add(((signed as i64) << 2) as u64)
}

// Operand decoders for the ADRP-pair / data-ref instruction shapes.
//
// disarm64 classifies each word into an `Operation` but its bit-extraction
// helpers are `pub(crate)`, so we read the operand fields ourselves. These
// decoders are the single place each field layout is hand-written: both the
// data-ref recovery ([`detect_data_ref`]) and the masker ([`mask_lo12_pair`])
// consume them, so a copy-pasted shift/mask constant can't leave a `lo12`
// unmasked in one path but not the other.

/// Location of a contiguous immediate field within a 32-bit A64 word.
/// Sharing `(lsb, width)` keeps value-decode and masking on the same bits.
#[derive(Clone, Copy)]
struct ImmField {
    lsb: u32,
    width: u32,
}
impl ImmField {
    /// Extract the raw (unsigned, unshifted) field value.
    fn extract(self, bits: u32) -> u32 {
        (bits >> self.lsb) & ((1u32 << self.width) - 1)
    }
    /// Zero the field, leaving every other bit untouched.
    fn clear(self, bits: u32) -> u32 {
        bits & !(((1u32 << self.width) - 1) << self.lsb)
    }
}

/// `lo12` immediate of `ADD (imm)` and `LDR/STR (unsigned imm12)`: bits [21:10].
const IMM12_FIELD: ImmField = ImmField { lsb: 10, width: 12 };
/// Immediate of `LDUR/STUR (unscaled imm9)`: bits [20:12].
const IMM9_FIELD: ImmField = ImmField { lsb: 12, width: 9 };

/// Decoded `ADRP`/`ADR` (PCRELADDR class).
struct PcRelAddr {
    /// True for `ADRP` (page-aligned, `<<12`); false for `ADR`.
    is_adrp: bool,
    /// Destination register (31 = XZR, which discards the result).
    rd: u8,
    /// Absolute address the instruction forms relative to `ip`.
    target: u64,
}
fn decode_pcreladdr(bits: u32, ip: u64) -> PcRelAddr {
    let immlo = (bits >> 29) & 0x3;
    let immhi = (bits >> 5) & 0x7_FFFF;
    // 21-bit immediate (immhi:immlo), sign-extended.
    let imm = (((immhi << 2) | immlo) as i32) << 11 >> 11;
    let is_adrp = (bits >> 31) & 1 == 1;
    let target = if is_adrp {
        // ADRP: page-aligned PC + (imm << 12).
        (ip & !0xFFF).wrapping_add(((imm as i64) << 12) as u64)
    } else {
        // ADR: full address, no shift.
        ip.wrapping_add(imm as i64 as u64)
    };
    PcRelAddr {
        is_adrp,
        rd: (bits & 0x1F) as u8,
        target,
    }
}

/// Decoded `ADD (immediate)` fields relevant to ADRP-pair `lo12` handling.
struct AddImm {
    /// 64-bit operation (`sf == 1`); the ADRP+ADD form is always 64-bit.
    sf: u32,
    /// Shift-by-12 flag (`sh`); the ADRP+ADD form is always unshifted.
    sh: u32,
    /// Unsigned 12-bit immediate (no scaling).
    imm: u32,
    rn: u8,
    rd: u8,
}
fn decode_add_imm(bits: u32) -> AddImm {
    AddImm {
        sf: (bits >> 31) & 1,
        sh: (bits >> 22) & 1,
        imm: IMM12_FIELD.extract(bits),
        rn: ((bits >> 5) & 0x1F) as u8,
        rd: (bits & 0x1F) as u8,
    }
}

/// Decoded load/store-with-immediate fields, unifying the unsigned-scaled
/// (`LDST_POS`) and signed-unscaled (`LDST_UNSCALED`) forms (the two
/// load/store shapes that can complete an ADRP `lo12` pair).
struct LdStImm {
    rn: u8,
    rt: u8,
    /// Byte offset from `Rn`, already scaled (`POS`) / sign-extended (`UNSCALED`).
    offset: i64,
    /// Width of the memory access in bytes.
    access_bytes: u32,
    /// True if `Rt` is written from memory (a load), so it can no longer
    /// continue an address chain. False for stores.
    is_load: bool,
    /// Bit position of the relocatable immediate, for masking.
    imm_field: ImmField,
}
fn decode_ldst_pos(bits: u32) -> LdStImm {
    // size:2 111 V 01 opc:2 imm12:12 Rn:5 Rt:5. Offset = imm12 << size.
    let size = (bits >> 30) & 0x3;
    let opc = (bits >> 22) & 0x3;
    LdStImm {
        rn: ((bits >> 5) & 0x1F) as u8,
        rt: (bits & 0x1F) as u8,
        offset: ((IMM12_FIELD.extract(bits) as u64) << size) as i64,
        access_bytes: 1u32 << size,
        is_load: opc != 0,
        imm_field: IMM12_FIELD,
    }
}
fn decode_ldst_unscaled(bits: u32) -> LdStImm {
    // size:2 111 V 00 opc:2 0 imm9:9 00 Rn:5 Rt:5. Signed 9-bit offset.
    let size = (bits >> 30) & 0x3;
    let opc = (bits >> 22) & 0x3;
    let imm9 = IMM9_FIELD.extract(bits) as i32;
    LdStImm {
        rn: ((bits >> 5) & 0x1F) as u8,
        rt: (bits & 0x1F) as u8,
        offset: ((imm9 << 23) >> 23) as i64,
        access_bytes: 1u32 << size,
        is_load: opc != 0,
        imm_field: IMM9_FIELD,
    }
}

/// Decoded `LDR (literal)` (LOADLIT class). Returns `None` for the `PRFM`
/// (prefetch) literal form, which moves no data.
struct LoadLit {
    rt: u8,
    target: u64,
    access_bytes: u32,
}
fn decode_loadlit(bits: u32, ip: u64) -> Option<LoadLit> {
    // opc:2 011 V 00 imm19:19 Rt:5. Address = PC + (imm19 << 2).
    let access_bytes = match (bits >> 30) & 0x3 {
        0 => 4,           // LDR Wt
        1 => 8,           // LDR Xt
        2 => 4,           // LDRSW
        _ => return None, // PRFM (literal): no data movement
    };
    let imm19 = ((bits >> 5) & 0x7_FFFF) as i32;
    let off = (imm19 << 13) >> 13;
    Some(LoadLit {
        rt: (bits & 0x1F) as u8,
        target: ip.wrapping_add(((off as i64) << 2) as u64),
        access_bytes,
    })
}

/// aarch64 recursive-descent function analyzer backend.
pub struct Arm64Isa;

impl InstructionSet for Arm64Isa {
    fn analyze_function(&self, mem: &dyn MemoryView, va: u64) -> Result<FunctionAnalysis> {
        analyze_function(mem, va)
    }
}

/// Recursive-descent function analyzer for A64. Mirrors the x86 path:
/// walks reachable instructions from `va`, records direct calls,
/// accumulates basic-block boundaries, and recovers data references inline
/// via [`detect_data_ref`] as each instruction is decoded.
fn analyze_function(mem: &dyn MemoryView, va: u64) -> Result<FunctionAnalysis> {
    let mut analysis = FunctionAnalysis {
        entry_point: va,
        ..Default::default()
    };

    // 256 KiB: UE init / vtable-population functions can exceed 64 KiB. Only
    // matters for starts found via call-graph descent (no end hint); with an
    // FDE end, `fde_cap` below clamps to the real end.
    let max_scan: usize = 0x40000;
    // Used only when there is no FDE end: a forward `B` whose target sits
    // more than this far past the highest visited instruction is treated as a
    // tail call. Without this guard a tail jump into a neighbouring function
    // would merge that function's body into ours.
    const TAIL_CALL_THRESHOLD: u64 = 0x50;

    // Map the function-region bytes once, capped at the FDE end when known.
    // Descent past the real end (e.g. through `BL __stack_chk_fail`, which
    // never returns, falling through into the next function's prologue) is
    // the dominant source of size over-estimation on real binaries.
    let start_offset = mem.rva_to_file_offset(va.saturating_sub(mem.image_base()))?;
    let file_data = mem.raw_bytes();
    let available = file_data.len().saturating_sub(start_offset);
    let fde_end = mem.function_size_hint(va);
    let fde_cap = fde_end.map(|end| (end - va) as usize).unwrap_or(max_scan);
    let scan_size = max_scan.min(fde_cap).min(available);
    if scan_size < 4 {
        bail!("No bytes available to scan");
    }
    let bytes = &file_data[start_offset..start_offset + scan_size];

    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<u64> = VecDeque::new();
    // Deferred unconditional-branch targets, classified as "internal" only
    // if the function body grows close enough to encompass them.
    let mut tail_queue: VecDeque<(u64, u64)> = VecDeque::new(); // (target, branch_ip)
    let mut block_intervals: BTreeSet<BlockBound> = Default::default();
    // Per-path ADRP/ADR register state: register index (0..=30) -> the
    // absolute address it currently holds. ADRP populates the entry; a later
    // `ADD/LDR/STR (imm)` using it as base consumes it into a DataReference.
    // Cleared on every non-Next flow: cross-block taint after a branch/call
    // is unreliable and BL clobbers caller-saved regs by ABI.
    let mut adrp_state: HashMap<u8, u64> = HashMap::new();

    queue.push_back(va);
    block_intervals.insert(BlockBound::Start(va));
    let mut max_address = va;

    debug!(
        target: "binfold::arch::size",
        start = format!("0x{va:x}"),
        "Starting arm64 recursive descent"
    );

    while let Some(start_ip) = queue.pop_front() {
        let mut ip = start_ip;
        adrp_state.clear();
        // Step until a terminator or already-seen address. A64's fixed 4-byte
        // width means no `set_position` dance.
        loop {
            if visited.contains(&ip) {
                break;
            }
            // Out-of-window?
            let Some(offset) = ip.checked_sub(va).map(|d| d as usize) else {
                break;
            };
            if offset + 4 > scan_size {
                break;
            }
            let (bits, opcode, flow) = match decode_op(bytes, offset, ip) {
                Some(t) => t,
                None => {
                    // Unrecognised encoding: skip it, treat as opaque.
                    trace!(
                        target: "binfold::arch::size",
                        address = format!("0x{ip:x}"),
                        "arm64 decode failed; treating as opaque next"
                    );
                    visited.insert(ip);
                    ip += 4;
                    if ip > max_address {
                        max_address = ip;
                    }
                    continue;
                }
            };
            visited.insert(ip);
            let next_ip = ip + 4;
            if next_ip > max_address {
                max_address = next_ip;
            }

            // Data-ref detection runs before flow handling on every
            // instruction; it mutates `adrp_state` and may push data refs.
            detect_data_ref(
                &opcode,
                bits,
                ip,
                mem,
                &mut adrp_state,
                &mut analysis.data_refs,
            );

            match flow {
                Flow::Next | Flow::IndirectCall => {
                    // An indirect call on a fall-through path clobbers
                    // caller-saved regs, so drop tracked addresses.
                    if matches!(flow, Flow::IndirectCall) {
                        adrp_state.clear();
                    }
                    ip = next_ip;
                }
                Flow::Call { target } => {
                    analysis.calls.push(FunctionCall {
                        address: ip,
                        target,
                    });
                    adrp_state.clear();
                    ip = next_ip;
                }
                Flow::UncondBranch { target } => {
                    block_intervals.insert(BlockBound::End(next_ip));
                    if target >= va && (target - va) < scan_size as u64 {
                        // In-window: classification depends on how far past
                        // `max_address` the target sits, so defer to the
                        // tail-call queue (drained at the end of each outer
                        // iteration, once `max_address` may have grown).
                        tail_queue.push_back((target, ip));
                    } else {
                        // Out-of-window: record a tail call to keep the
                        // call-graph connected.
                        analysis.calls.push(FunctionCall {
                            address: ip,
                            target,
                        });
                        // Linker veneers: when a relative offset can't be
                        // encoded, lld/bfd insert a thunk far outside the
                        // function that branches back to `next_ip`. If FDE
                        // bounds say the function continues past `next_ip`,
                        // queue it so descent picks up the post-veneer code.
                        if let Some(end) = fde_end
                            && next_ip < end
                        {
                            queue.push_back(next_ip);
                            block_intervals.insert(BlockBound::Start(next_ip));
                        }
                    }
                    break;
                }
                Flow::CondBranch { target } => {
                    // Fall-through becomes the start of a new block.
                    block_intervals.insert(BlockBound::Start(next_ip));
                    if target >= va && (target - va) < scan_size as u64 {
                        queue.push_back(target);
                        block_intervals.insert(BlockBound::Start(target));
                    }
                    ip = next_ip;
                }
                Flow::IndirectBranch | Flow::Return | Flow::Exception => {
                    if next_ip < va + scan_size as u64 {
                        block_intervals.insert(BlockBound::End(next_ip));
                    }
                    break;
                }
            }
        }

        // Drain the tail-call queue. With FDE bounds, any target inside
        // `[va, fde_end)` is internal; this catches forward branches that
        // jump well past the visited high-water mark in non-linear layouts
        // (compiler-split loops, jump-table fall-throughs) which would
        // otherwise look like tail calls and truncate the function.
        //
        // Without an FDE end, fall back to the `max_address +
        // TAIL_CALL_THRESHOLD` heuristic and also reject any target landing
        // exactly on a known FDE function start, so FDE-less dispatch shims
        // don't over-scan into the adjacent function. FDE bounds are computed
        // once before analysis, so this stays deterministic across batches.
        tail_queue.retain(|&(target, branch_ip)| {
            let is_internal = match fde_end {
                Some(end) => target >= va && target < end,
                None => {
                    target < max_address + TAIL_CALL_THRESHOLD
                        && !mem.is_known_function_start(target)
                }
            };
            if is_internal {
                block_intervals.insert(BlockBound::Start(target));
                queue.push_back(target);
                false
            } else {
                analysis.calls.push(FunctionCall {
                    address: branch_ip,
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

    // Convert sorted block bounds into [start, end) ranges (same algorithm
    // as the x86 path).
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
    if let Some(s) = start
        && s != max_address
    {
        analysis.basic_blocks.insert(s, max_address);
    }

    debug!(
        target: "binfold::arch::size",
        start = format!("0x{va:x}"),
        end = format!("0x{max_address:x}"),
        size = format!("0x{size:x}"),
        blocks = analysis.basic_blocks.len(),
        "arm64 function size analysis complete"
    );

    Ok(analysis)
}

/// WARP byte masker for aarch64. Wraps [`block_warp_bytes`], owning the ADRP
/// register-taint word so it threads across the blocks of one function.
/// Construct fresh per function via `Default`.
#[derive(Default)]
pub struct Arm64Masker {
    taint: u32,
}

impl crate::arch::BlockMasker for Arm64Masker {
    fn mask(&mut self, raw: &[u8], va: u64, bounds: Range<u64>) -> Vec<u8> {
        block_warp_bytes(raw, va, bounds, &mut self.taint)
    }
}

/// Emit the WARP-hashable byte stream for one basic block: skip NOP padding
/// and zero PC-relative immediates that would otherwise leak the load address
/// into the hash.
///
/// On A64 a global address is materialised by a pair: `ADRP Xn, page` then
/// `ADD Xn, Xn, #lo12` or `LDR/STR Xt, [Xn, #lo12]`. The linker resolves the
/// `lo12` into the low bits of the absolute symbol address, so it moves on
/// every build. Zeroing only the `ADRP` would leave that `lo12` in the hash
/// and make nearly every globals-referencing function build-specific, so we
/// track which registers hold an ADRP/ADR address (mirroring
/// [`detect_data_ref`]) and zero the `lo12` of any `ADD`/`LDR`/`STR` using
/// one. Only the relocatable immediate is masked; register and opcode bits
/// are kept.
///
/// `tainted` carries this register-taint across blocks, because a page is
/// often formed once in the prologue into a callee-saved register and used by
/// several later blocks. The caller threads one taint word through the blocks
/// in address order; calls clear the caller-saved half (x0-x18, x30) per the
/// AArch64 PCS, so a callee-saved page survives a call and a scratch one does
/// not.
pub fn block_warp_bytes(
    raw_bytes: &[u8],
    base_ip: u64,
    function_bounds: Range<u64>,
    tainted: &mut u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw_bytes.len());
    // Bit i set => register i holds an ADRP/ADR-derived address. Registers
    // 0..=30; reg 31 (XZR/SP) is never tracked.
    let set_taint = |t: &mut u32, r: u8| {
        if r < 31 {
            *t |= 1 << r;
        }
    };
    let clear_taint = |t: &mut u32, r: u8| {
        if r < 31 {
            *t &= !(1 << r);
        }
    };
    let is_tainted = |t: u32, r: u8| r < 31 && (t & (1 << r)) != 0;
    // GP registers clobbered across a call: x0-x18 and x30 (LR). x19-x29 are
    // callee-saved and keep their ADRP page across the call.
    const CALL_CLOBBER: u32 = ((1u32 << 19) - 1) | (1 << 30);

    let mut off = 0;
    while off + 4 <= raw_bytes.len() {
        let mut bits = u32::from_le_bytes([
            raw_bytes[off],
            raw_bytes[off + 1],
            raw_bytes[off + 2],
            raw_bytes[off + 3],
        ]);
        let ip = base_ip + off as u64;

        // Skip canonical NOPs (alignment / scheduling padding).
        if bits == NOP_BITS {
            off += 4;
            continue;
        }

        // Unrecognised encoding: keep the raw bytes. A decode failure can
        // only false-positive an in-bounds match, never alter an equal hash.
        if let Some(op) = decoder::decode(bits) {
            // Calls clobber caller-saved registers before the next
            // instruction's masking decision.
            if matches!(
                classify_flow(&op, bits, ip),
                Flow::Call { .. } | Flow::IndirectCall
            ) {
                *tainted &= !CALL_CLOBBER;
            }

            if is_relocatable(&op, bits, ip, &function_bounds) {
                // Whole-instruction zero (ADRP/ADR, LDR-literal, BL,
                // out-of-bounds branches). PCRELADDR also seeds the taint so
                // the paired lo12 instruction is caught.
                if matches!(op.operation, Operation::PCRELADDR(_)) {
                    let rd = (bits & 0x1F) as u8;
                    set_taint(tainted, rd);
                }
                bits = 0;
            } else {
                // Mask the lo12 immediate of an ADRP-paired ADD/LDR/STR.
                mask_lo12_pair(
                    &op,
                    &mut bits,
                    tainted,
                    &set_taint,
                    &clear_taint,
                    &is_tainted,
                );
            }
        }

        out.extend_from_slice(&bits.to_le_bytes());
        off += 4;
    }
    out
}

/// Update `tainted` for one instruction and, when it is the `lo12` half of an
/// `ADRP` pair, zero its immediate field in `bits`. Kept in lockstep with the
/// register-state transitions in [`detect_data_ref`] so masking decisions and
/// recovered data refs never disagree.
fn mask_lo12_pair(
    op: &Opcode,
    bits: &mut u32,
    tainted: &mut u32,
    set_taint: &dyn Fn(&mut u32, u8),
    clear_taint: &dyn Fn(&mut u32, u8),
    is_tainted: &dyn Fn(u32, u8) -> bool,
) {
    match &op.operation {
        Operation::ADDSUB_IMM(_) if matches!(op.mnemonic, Mnemonic::add) => {
            let a = decode_add_imm(*bits);
            // Only the 64-bit, unshifted ADD off a tainted base is an
            // ADRP+ADD pair: its lo12 is relocatable and must be zeroed, and
            // the formed address propagates to Rd. Anything else overwrites
            // Rd with a non-address value and breaks the chain.
            if a.sf == 1 && a.sh == 0 && is_tainted(*tainted, a.rn) {
                *bits = IMM12_FIELD.clear(*bits);
                set_taint(tainted, a.rd);
            } else {
                clear_taint(tainted, a.rd);
            }
        }
        Operation::LDST_POS(_) => mask_ldst(
            decode_ldst_pos(*bits),
            bits,
            tainted,
            clear_taint,
            is_tainted,
        ),
        Operation::LDST_UNSCALED(_) => mask_ldst(
            decode_ldst_unscaled(*bits),
            bits,
            tainted,
            clear_taint,
            is_tainted,
        ),
        _ => {
            // Other encodings: leave taint untouched. A stale-taint false
            // mask is rare and only zeroes a few immediate bits.
        }
    }
}

/// Masking half of the load/store `lo12` handling, shared by the scaled and
/// unscaled forms (see [`decode_ldst_pos`] / [`decode_ldst_unscaled`]): zero
/// the relocatable immediate when the base register holds an ADRP page, and
/// drop a loaded destination from the taint set.
fn mask_ldst(
    f: LdStImm,
    bits: &mut u32,
    tainted: &mut u32,
    clear_taint: &dyn Fn(&mut u32, u8),
    is_tainted: &dyn Fn(u32, u8) -> bool,
) {
    if is_tainted(*tainted, f.rn) {
        *bits = f.imm_field.clear(*bits);
    }
    // A load clobbers Rt with memory contents, no longer an address.
    if f.is_load {
        clear_taint(tainted, f.rt);
    }
}

/// Inspect a decoded instruction for data-reference patterns and update the
/// per-path ADRP tracking state. Recognised patterns:
///
///   * `ADRP Xd, page`: populate state[Xd] = page-aligned addr
///   * `ADR Xd, label`: emit a data_ref and populate state[Xd]
///   * `ADD Xd, Xn, #imm`: if state[Xn], emit data_ref(state[Xn]+imm) and
///     propagate the address into Xd
///   * `LDR/STR (imm, unsigned)`: if state[Xn], emit
///     data_ref(state[Xn]+(imm12 << size)); loads drop Xt from state
///   * `LDR/STR (imm9 unscaled)`: same, signed 9-bit offset
///   * `LDR (literal)`: emit data_ref(ip + (imm19 << 2)) directly
///
/// Unrecognised instructions leave state alone. The resulting risk of a bogus
/// data_ref from stale state is filtered out downstream by `read_string_data`.
fn detect_data_ref(
    op: &Opcode,
    bits: u32,
    ip: u64,
    mem: &dyn MemoryView,
    state: &mut HashMap<u8, u64>,
    out: &mut Vec<DataReference>,
) {
    let push_ref = |out: &mut Vec<DataReference>, address: u64, target: u64, size: Option<u32>| {
        out.push(DataReference {
            address,
            target,
            is_readonly: !mem.is_address_writable(target).unwrap_or(false),
            estimated_size: size,
        });
    };

    match &op.operation {
        Operation::PCRELADDR(_) => {
            let p = decode_pcreladdr(bits, ip);
            if p.rd == 31 {
                // XZR write: discarded, nothing to track or emit.
                return;
            }
            if p.is_adrp {
                // Page address only; the data ref is emitted when the paired
                // lo12 ADD/LDR/STR consumes this register.
                state.insert(p.rd, p.target);
            } else {
                // ADR forms the full address: record it and seed state for
                // any chained ADD.
                push_ref(out, ip, p.target, None);
                state.insert(p.rd, p.target);
            }
        }
        Operation::ADDSUB_IMM(_) if matches!(op.mnemonic, Mnemonic::add) => {
            let a = decode_add_imm(bits);
            // ADRP+ADD requires sf=1 (64-bit) and sh=0 (no shift).
            if a.sf == 0 || a.sh == 1 {
                // Dest is overwritten with a non-statically-computable value.
                if a.rd != 31 {
                    state.remove(&a.rd);
                }
                return;
            }
            if let Some(&page) = state.get(&a.rn) {
                let target = page.wrapping_add(a.imm as u64);
                push_ref(out, ip, target, None);
                if a.rd != 31 {
                    state.insert(a.rd, target);
                }
            } else if a.rd != 31 {
                state.remove(&a.rd);
            }
        }
        Operation::LDST_POS(_) => {
            if let Some((target, size)) = detect_ldst(decode_ldst_pos(bits), state) {
                push_ref(out, ip, target, Some(size));
            }
        }
        Operation::LDST_UNSCALED(_) => {
            if let Some((target, size)) = detect_ldst(decode_ldst_unscaled(bits), state) {
                push_ref(out, ip, target, Some(size));
            }
        }
        Operation::LOADLIT(_) => {
            let Some(l) = decode_loadlit(bits, ip) else {
                return; // PRFM (literal): no data movement
            };
            push_ref(out, ip, l.target, Some(l.access_bytes));
            // LDR-literal writes Rt with the loaded value; drop it.
            if l.rt != 31 {
                state.remove(&l.rt);
            }
        }
        _ => {
            // Unrecognised encodings: don't invalidate destinations. Any
            // false-positive data ref from stale state is filtered out by
            // the readability check in `read_string_data`.
        }
    }
}

/// Data-ref recovery half of the load/store handling, shared by the scaled
/// and unscaled forms. Returns `Some((target, access_bytes))` when the base
/// register holds an ADRP page (the caller records the `data_ref`), and drops
/// a loaded destination from the tracking state (its value is now memory
/// contents, not an address).
fn detect_ldst(f: LdStImm, state: &mut HashMap<u8, u64>) -> Option<(u64, u32)> {
    let dref = state
        .get(&f.rn)
        .map(|&page| (page.wrapping_add(f.offset as u64), f.access_bytes));
    if f.is_load && f.rt != 31 {
        state.remove(&f.rt);
    }
    dref
}

/// True if this instruction's bytes must be zeroed before hashing. See the
/// module-level "WARP-relevant masking" list for the rules.
pub fn is_relocatable(op: &Opcode, bits: u32, ip: u64, func_bounds: &Range<u64>) -> bool {
    match &op.operation {
        // PC-relative address formation: always position-dependent.
        Operation::PCRELADDR(_) => true,
        // LDR (literal): PC-relative load.
        Operation::LOADLIT(_) => true,
        // Direct call: always.
        Operation::BRANCH_IMM(_) if matches!(op.mnemonic, Mnemonic::bl) => true,
        // Direct unconditional branch: only if it leaves the function (tail
        // call); intra-function branches are stable bytes.
        Operation::BRANCH_IMM(_) => !func_bounds.contains(&branch_target_imm26(bits, ip)),
        // Conditional branches: same rule.
        Operation::CONDBRANCH(_) | Operation::COMPBRANCH(_) => {
            !func_bounds.contains(&branch_target_imm19(bits, ip))
        }
        Operation::TESTBRANCH(_) => !func_bounds.contains(&branch_target_imm14(bits, ip)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden encodings, verified against an assembler. These lock the
    // hand-written field layouts so the data-ref and masking paths (which
    // both consume these decoders) can't silently drift.

    #[test]
    fn add_imm_fields_and_mask() {
        // add x0, x1, #0x10  ->  0x91004020
        let bits = 0x9100_4020;
        let a = decode_add_imm(bits);
        assert_eq!((a.sf, a.sh, a.imm, a.rn, a.rd), (1, 0, 0x10, 1, 0));
        // Masking zeroes only imm12 (bits [21:10]): add x0, x1, #0 = 0x91000020
        assert_eq!(IMM12_FIELD.clear(bits), 0x9100_0020);
    }

    #[test]
    fn ldst_pos_scaled_offset() {
        // ldr x0, [x1, #8]  ->  0xF9400420  (imm12=1, scaled by size=3)
        let f = decode_ldst_pos(0xF940_0420);
        assert_eq!(
            (f.rn, f.rt, f.offset, f.access_bytes, f.is_load),
            (1, 0, 8, 8, true)
        );
        assert_eq!(f.imm_field.lsb, IMM12_FIELD.lsb);
        // str x0, [x1, #8]  ->  0xF9000420  (opc=00 => store, not a load)
        let s = decode_ldst_pos(0xF900_0420);
        assert!(!s.is_load);
    }

    #[test]
    fn ldst_unscaled_signed_offset() {
        // stur x0, [x1, #-8]  ->  0xF81F8020  (imm9 = -8, unscaled)
        let f = decode_ldst_unscaled(0xF81F_8020);
        assert_eq!((f.rn, f.rt, f.offset, f.is_load), (1, 0, -8, false));
        assert_eq!(f.imm_field.lsb, IMM9_FIELD.lsb);
    }

    #[test]
    fn pcreladdr_adrp_and_adr() {
        // adrp x0, #0x1000 at ip 0  ->  0xB0000000, page target 0x1000
        let p = decode_pcreladdr(0xB000_0000, 0);
        assert!(p.is_adrp);
        assert_eq!((p.rd, p.target), (0, 0x1000));
        // adr x0, #4 at ip 0  ->  0x10000020, full target 4
        let a = decode_pcreladdr(0x1000_0020, 0);
        assert!(!a.is_adrp);
        assert_eq!((a.rd, a.target), (0, 4));
    }

    #[test]
    fn loadlit_target_and_prfm() {
        // ldr x0, #8 (literal) at ip 0  ->  0x58000040
        let l = decode_loadlit(0x5800_0040, 0).expect("LDR literal decodes");
        assert_eq!((l.rt, l.target, l.access_bytes), (0, 8, 8));
        // prfm form (opc=11) yields no data ref
        assert!(decode_loadlit(0xD800_0040, 0).is_none());
    }

    #[test]
    fn branch_targets_signed() {
        // bl #4  ->  0x94000001 ; bl #-4 from ip 4 lands at 0
        assert_eq!(branch_target_imm26(0x9400_0001, 0), 4);
        assert_eq!(branch_target_imm26(0x97FF_FFFF, 4), 0);
    }

    #[test]
    fn imm_field_roundtrip() {
        let f = ImmField { lsb: 10, width: 12 };
        assert_eq!(f.extract(0xFFFF_FFFF), 0xFFF);
        assert_eq!(f.clear(0xFFFF_FFFF), 0xFFC0_03FF);
    }
}
