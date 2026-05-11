//! Function-pointer site index.
//!
//! Scans read-only initialized-data sections (the `.rdata` class) for
//! pointer-sized words whose value matches a known function entry point.
//! Each such word is a `FnPtrSite` — typically a slot inside a C++ vtable,
//! an RTTI thunk table, a static function-pointer table, etc.
//!
//! No vtable structure is reconstructed. There is no concept of "vtable
//! base" or "vtable size" here — adjacency between sites is determined
//! entirely by exact pointer-grid address arithmetic, so callers can ask
//! "is there a site at `s.data_addr + k * ptr_size`?" without committing
//! to where a vtable starts or ends.
//!
//! Intended consumers (e.g. the fuzzy matcher) use the reverse index
//! `func -> [sites]` to give virtual functions a topology: a virtual is
//! reached only through indirect dispatch, so `func.calls` never lists it
//! as a target, but its grid neighbors in RO data are a stable proxy for
//! "who lives next to me in the class layout".

use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::pe_loader::PeLoader;

// PE section characteristics. Duplicated from pe_loader.rs rather than
// pulled in as `pub` constants to keep this module self-contained.
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// One occurrence of a function pointer in initialized data: the
/// pointer-sized word at `data_addr` reads as `func`, which is a known
/// function entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FnPtrSite {
    pub data_addr: u64,
    pub func: u64,
}

/// All function-pointer sites in a PE's read-only data, plus reverse
/// indexes for the two queries consumers need:
///   - "where in RO data is function F referenced from?" -> `sites_of(F)`
///   - "is there a fn-ptr at this exact data address?"   -> `site_at(addr)`
pub struct FnPtrIndex {
    /// Pointer width in bytes (4 on PE32, 8 on PE64). All grid
    /// arithmetic uses this step.
    ptr_size: u64,
    /// All discovered sites, sorted ascending by `data_addr`.
    sites: Vec<FnPtrSite>,
    /// `data_addr` -> index into `sites`. Probed by `grid_neighbor` to
    /// answer "is there a fn-ptr at exactly addr X?".
    by_addr: FxHashMap<u64, u32>,
    /// `func` -> indices into `sites`. A function may appear in multiple
    /// vtables (multiple inheritance) or in several slots of one vtable
    /// (ICF-folded virtuals), so the value is a Vec.
    by_func: FxHashMap<u64, Vec<u32>>,
}

impl FnPtrIndex {
    /// Pointer width in bytes (4 or 8).
    pub fn ptr_size(&self) -> u64 {
        self.ptr_size
    }

    /// All discovered sites, in ascending `data_addr` order.
    pub fn sites(&self) -> &[FnPtrSite] {
        &self.sites
    }

    /// Lookup by site index. Panics on out-of-range index — the only
    /// indices ever handed out come from this struct, so a bad index is
    /// a programming error, not user input.
    pub fn site(&self, idx: u32) -> FnPtrSite {
        self.sites[idx as usize]
    }

    /// Site at exactly `data_addr`, or `None` if no function pointer
    /// lives there.
    pub fn site_at(&self, data_addr: u64) -> Option<FnPtrSite> {
        self.by_addr
            .get(&data_addr)
            .map(|&i| self.sites[i as usize])
    }

    /// All site indices whose function is `func`. Empty slice if `func`
    /// is not referenced from RO data (a typical non-virtual function).
    pub fn sites_of(&self, func: u64) -> &[u32] {
        self.by_func.get(&func).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Site at `from.data_addr + offset_slots * ptr_size`, if one
    /// exists. `offset_slots` is signed and measured in pointer-sized
    /// slots (not bytes). `offset_slots == 0` returns `None` — callers
    /// asking about a peer wouldn't typically want self back.
    pub fn grid_neighbor(&self, from: FnPtrSite, offset_slots: i32) -> Option<FnPtrSite> {
        if offset_slots == 0 {
            return None;
        }
        let step = (offset_slots as i64).checked_mul(self.ptr_size as i64)?;
        let addr = (from.data_addr as i64).checked_add(step)?;
        if addr < 0 {
            return None;
        }
        self.site_at(addr as u64)
    }

    pub fn len(&self) -> usize {
        self.sites.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    /// Number of distinct functions referenced from at least one site.
    pub fn distinct_funcs(&self) -> usize {
        self.by_func.len()
    }
}

/// Scan all read-only initialized-data sections for pointer-sized words
/// whose value is a known function entry point.
///
/// `func_entries` is the set of entry-point VAs to recognize — typically
/// `funcs.iter().map(|f| f.entry_point).collect()` from a prior
/// `PeLoader::find_all_functions` pass. Words pointing into `.text` at
/// addresses *not* in this set are deliberately ignored: anchoring
/// against function-discovery output is what keeps the false-positive
/// rate low for stray pointer-shaped qwords.
///
/// Cost: O(rdata_bytes / ptr_size) with one hashmap probe per word. On
/// a ~10MB `.rdata` this is a few milliseconds.
pub fn find_fn_ptr_sites(pe: &PeLoader, func_entries: &FxHashSet<u64>) -> Result<FnPtrIndex> {
    let ptr_size: u64 = match pe.bitness() {
        32 => 4,
        64 => 8,
        b => anyhow::bail!("unsupported PE bitness: {b}"),
    };
    let image_base = pe.image_base();

    let mut sites: Vec<FnPtrSite> = Vec::new();

    for section in pe.sections() {
        let c = section.characteristics;
        // .rdata-class: initialized data, not executable, not writable.
        // - Skipping executable sections excludes `.text` (where the
        //   notion of "data adjacency" doesn't apply).
        // - Skipping writable sections excludes `.data` and `.bss`,
        //   which can legitimately hold function pointers (callback
        //   slots, runtime hooks) but rarely host vtables and inflate
        //   the noise floor when scanned.
        if (c & IMAGE_SCN_CNT_INITIALIZED_DATA) == 0 {
            continue;
        }
        if (c & IMAGE_SCN_MEM_EXECUTE) != 0 {
            continue;
        }
        if (c & IMAGE_SCN_MEM_WRITE) != 0 {
            continue;
        }

        let start_va = image_base + section.virtual_address as u64;
        // virtual_size can exceed size_of_raw_data when the section has
        // trailing zero-fill; we can only read what's actually on disk.
        let raw_size = section.size_of_raw_data as usize;
        let virt_size = section.virtual_size as usize;
        let size = raw_size.min(virt_size);
        if size < ptr_size as usize {
            continue;
        }

        let bytes = match pe.read_at_va(start_va, size) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Stride at pointer-alignment. ABI-aligned function pointers
        // (vtables, dispatch tables) land on this grid; an unaligned
        // qword that happens to look like a code pointer is extremely
        // unlikely to be a real entry and would just be noise.
        let step = ptr_size as usize;
        let mut off: usize = 0;
        while off + step <= bytes.len() {
            let val: u64 = match step {
                4 => {
                    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
                        as u64
                }
                8 => u64::from_le_bytes([
                    bytes[off],
                    bytes[off + 1],
                    bytes[off + 2],
                    bytes[off + 3],
                    bytes[off + 4],
                    bytes[off + 5],
                    bytes[off + 6],
                    bytes[off + 7],
                ]),
                _ => unreachable!(),
            };
            if func_entries.contains(&val) {
                sites.push(FnPtrSite {
                    data_addr: start_va + off as u64,
                    func: val,
                });
            }
            off += step;
        }
    }

    sites.sort_unstable_by_key(|s| s.data_addr);

    let mut by_addr: FxHashMap<u64, u32> = FxHashMap::default();
    by_addr.reserve(sites.len());
    let mut by_func: FxHashMap<u64, Vec<u32>> = FxHashMap::default();
    for (i, s) in sites.iter().enumerate() {
        let idx = i as u32;
        by_addr.insert(s.data_addr, idx);
        by_func.entry(s.func).or_default().push(idx);
    }

    Ok(FnPtrIndex {
        ptr_size,
        sites,
        by_addr,
        by_func,
    })
}
