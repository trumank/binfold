//! Hack: feeds binfold's x86 analysis into grapnel's MinHash/LSH engine.
//!
//! Builds one Graph<u64> per binary (nodes = functions, edges = direct calls)
//! and runs `match_graphs` to produce a map of base-binary function addresses
//! to target-binary function addresses.

use anyhow::Result;
use binfold::mmap_source::MmapSource;
use binfold::pe_loader::{FunctionAnalysis, PeLoader};
use binfold::warp::read_string_data;
use clap::Parser;
use grapnel::{Feature, Graph, MatcherConfig, UniversalMinHash};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use pdb::{FallibleIterator, PDB, SymbolData};
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

#[derive(Parser, Clone)]
#[command(about = "Fuzzy-match functions between two PEs using grapnel")]
struct Args {
    base: PathBuf,
    target: PathBuf,

    /// MinHash permutations. Higher = sharper similarity estimates but more
    /// work per node. K=800 was the diminishing-returns point in tuning.
    #[arg(long, default_value_t = 800)]
    k: usize,
    /// Number of LSH bands. Should track K to keep rows-per-band ≈ 8
    /// (effective LSH threshold around 0.5–0.7). K=200→25, K=400→50,
    /// K=800→100.
    #[arg(long, default_value_t = 100)]
    bands: usize,
    /// Minimum total feature weight for a node to enter the LSH index. With
    /// the current weights (bigram=1, str/imp/const=8, shape=4), a value of 4
    /// admits even sparse-feature functions; raising this filters out
    /// trivial stubs at the cost of recall.
    #[arg(long, default_value_t = 4)]
    min_features: u32,
    /// Minimum Jaccard similarity for a pair to be accepted as an anchor in
    /// Phase 3. The grapnel default of 0.72 was calibrated for rich
    /// same-compiler features; for cross-compiler with sparse stable
    /// features, 0.5 is the sweet spot.
    #[arg(long, default_value_t = 0.5)]
    anchor: f64,
    /// Minimum Jaccard similarity for graph propagation in Phase 4.
    #[arg(long, default_value_t = 0.2)]
    propagate: f64,
    /// Phase 4 hub filter: skip propagating from a matched pair if either
    /// side's call list exceeds this. Default 64 is calibrated for
    /// cross-compiler — Clang inlines less than MSVC, often producing
    /// 2-3× larger callee lists on the target side; the grapnel default of
    /// 16 was too tight and blocked otherwise-matchable propagation paths.
    #[arg(long, default_value_t = 64)]
    max_degree: usize,
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Print at most this many matches.
    #[arg(long, default_value_t = 50)]
    limit: usize,

    /// Validate matches against `.pdb` files next to each `.exe` and report
    /// precision (fraction of matched pairs whose PDB symbol names agree).
    #[arg(long)]
    validate: bool,

    /// Drop instruction bigrams. Useful for cross-compiler matching where
    /// instruction selection differs but strings/imports/constants don't.
    #[arg(long)]
    no_bigrams: bool,

    /// Bundle features from functions within this many call-graph hops into
    /// each node's signature. 0 = no bundling. Hops=2 was the sweet spot in
    /// tuning; hops=1 is too tight, hops=3 over-bundles into noise.
    #[arg(long, default_value_t = 2)]
    hops: usize,

    /// When bundling, skip expansion through any node with more incoming or
    /// outgoing edges than this. Prevents hub functions (memcpy, log,
    /// allocator wrappers) from polluting every neighborhood.
    #[arg(long, default_value_t = 32)]
    hub_degree: usize,

    /// Bundling direction. "callees" walks downward (semantic dependencies).
    /// "callers" walks upward (where F is used). "both" walks both.
    #[arg(long, default_value = "both", value_parser = ["callees", "callers", "both"])]
    bundle: String,

    /// Restrict which feature categories get propagated through bundling.
    /// Comma-separated subset of: bigram, import, string, const, blkcount,
    /// callcount. Default `import,string,const` is the asymmetric-bundling
    /// sweet spot: carries cross-compiler-stable identity through the
    /// neighborhood while keeping bigrams local. Set to "all" (any
    /// nonexistent category sentinel) is not supported — pass an empty value
    /// or omit the flag for the legacy "all categories propagate" behavior.
    #[arg(long, value_delimiter = ',', default_value = "import,string,const")]
    bundle_features: Option<Vec<String>>,

    /// After --validate, sample N "should-match" pairs (same name in both
    /// binaries) and dump their feature decomposition side-by-side. Splits
    /// into a TP cohort (algorithm matched correctly) and an FN cohort
    /// (algorithm missed or matched wrong). 0 = disabled.
    #[arg(long, default_value_t = 0)]
    inspect_samples: usize,

    /// Show feature comparison + callee list for any name containing this
    /// substring. Repeat for multiple patterns. Useful for digging into
    /// specific UE subsystems (e.g. --inspect-pattern FName).
    #[arg(long = "inspect-pattern")]
    inspect_patterns: Vec<String>,

    /// Cap on how many name matches per pattern to inspect.
    #[arg(long, default_value_t = 5)]
    inspect_pattern_limit: usize,

    /// Number of iterative anchor-rebuild passes. 1 = single match. >1 =
    /// after each pass, every confirmed pair `(a, b)` is assigned a
    /// synthetic identity feature `Feat::SyntCallee { depth, hash }` injected
    /// into functions that reach `a` (base) or `b` (target) within
    /// `--synt-depth` hops. Subsequent passes can then anchor functions on
    /// their *certified* call topology. Stable IDs are preserved across
    /// passes. **Default 2** when paired with `--synt-depth 2`: the multi-hop
    /// reach gets pass-3-equivalent topology coverage in pass 2, and pass 3
    /// then regresses (richer-but-asymmetric synth dilutes Jaccard via
    /// inlining-asymmetry). Use `--iterations 3` only with `--synt-depth 1`.
    #[arg(long, default_value_t = 2)]
    iterations: usize,

    /// One-at-a-time perturbation sweep around the current args. Loads PE
    /// and PDB once, then re-runs the matcher with each parameter
    /// individually perturbed across a few values, holding everything else
    /// fixed at whatever the user passed. Prints a sensitivity table to
    /// stdout — one block per parameter, with absolute prec/recall and
    /// delta vs baseline. Auto-enables --validate. Each perturbation costs
    /// one full match (~30s on 505S/SC); the full sweep is ~25-30 min.
    #[arg(long)]
    sweep: bool,

    /// Run a small grid of pre-defined combinations of the precision/recall
    /// levers identified by --sweep, to test for interactions (do
    /// precision-positive perturbations stack, or do they saturate?). Loads
    /// PE+PDB once. Auto-enables --validate. ~10-12 runs, ~6-8 min.
    #[arg(long)]
    sweep_combos: bool,

    /// Minimum number of LSH bands a candidate must collide in to be scored
    /// in Phase 2. With low rows-per-band (e.g. K=800 + bands=200 → rows=4),
    /// many low-J candidates leak through individual bands by chance and
    /// dominate Phase 2 cost. Requiring ≥2 collisions drops near-all J<0.3
    /// candidates while keeping J≥0.5 candidates with ~99% probability —
    /// near-free precision/speed in those regimes. Default 1 = original
    /// "any-band collision" behaviour.
    #[arg(long, default_value_t = 1)]
    min_band_collisions: usize,

    /// Write match results + synth maps to this file as a plain-text cache
    /// for graph_diff to consume. Decouples visualization from the matcher
    /// cycle — render graphs without re-running the 30s match each time.
    #[arg(long)]
    emit_matches: Option<PathBuf>,

    /// Multi-hop SyntCallee depth. **Default 2**: each pass BFS-walks up to
    /// 2 callee hops from each function and emits a depth-tagged synth
    /// feature for any reached callee whose pair was confirmed in a prior
    /// pass. Depth lives in the hash key so depth-1 and depth-2 don't
    /// collide; weight decays geometrically (16/8/4/2). Multi-hop reach in
    /// one pass collapses what previously took multiple iterations to
    /// achieve via single-hop propagation: depth=2 iter=2 is +0.31pp prec /
    /// +2.01pp recall / 28% faster than the prior depth=1 iter=3 default.
    /// Depth>=3 over-fits (asymmetric inlining dilutes Jaccard).
    #[arg(long, default_value_t = 2)]
    synt_depth: u8,
}

/// All features are pre-hashed to u64 for cheap hashing in the inner MinHash
/// loop, and tagged by kind so different feature spaces don't collide.
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
enum Feat {
    /// Pair of consecutive (Mnemonic, OpKind shape) tuples within a basic
    /// block. Compiler-coupled — disable for cross-compiler matching.
    Bigram(u64),
    /// Hash of an imported API name.
    Import(u64),
    /// Hash of a read-only string literal referenced by the function.
    StringLit(u64),
    /// A "magic" numeric immediate from the function body. Filtered to skip
    /// small values (0, 1, ±256) which appear everywhere and don't anchor.
    Const(i64),
    /// log2(block_count) — stable across small refactors.
    BlockCountBucket(u32),
    /// log2(call_count + 1) — number of call instructions, log-binned.
    CallCountBucket(u32),
    /// Wrapped hash of any feature originating from a neighbor. Tagged with
    /// the call-graph hop distance so own-features and neighbor-features live
    /// in separate spaces — F's own Bigram(x) doesn't collide with a
    /// neighbor's Bigram(x). Topology contributes signal without overwriting
    /// F's own identity.
    Nbr { depth: u8, hash: u64 },
    /// Synthetic callee identity from iterative anchor-rebuild. After a match
    /// pass, every confirmed pair `(a, b)` is assigned a unique synthetic ID
    /// `S`. With `--synt-depth 1` (default), depth=1 entries are emitted for
    /// every direct callee that has a synth ID — equivalent to the original
    /// `Feat::SyntCallee(S)`. With `--synt-depth N>1`, BFS reaches N hops
    /// and emits at each depth; depth lives in the hash key so depth-1 and
    /// depth-2 don't collide. This is a *certified* cross-binary identity
    /// feature: it's only ever created from confirmed matches.
    SyntCallee { depth: u8, hash: u64 },
}

impl Feature for Feat {
    fn weight(&self) -> u32 {
        match self {
            // Compiler-coupled identity signal. There are many bigrams per
            // function (median 25-100), so even at weight=1 they dominate by
            // count when no other features exist. Higher weight would let
            // them outvote stable cross-compiler signal.
            Feat::Bigram(_) => 1,
            // Compiler-stable identity. Few per function (often 0-3), so
            // weight them up so a single matching string/import/constant
            // can anchor a function whose bigrams have diverged.
            Feat::Import(_) | Feat::StringLit(_) | Feat::Const(_) => 8,
            // Coarse shape — always present, weakly distinctive. Mid-weight.
            Feat::BlockCountBucket(_) | Feat::CallCountBucket(_) => 4,
            // Neighborhood features decay with depth: 1-hop is more
            // informative than 3-hop. Both are still topology hints, not
            // identity.
            Feat::Nbr { depth, .. } => match depth {
                1 => 2,
                _ => 1,
            },
            // Certified cross-binary identity from a previous match pass.
            // Strongest signal at depth=1 (direct callee). Decays
            // geometrically with depth: depth=2 callees-of-callees carry
            // weaker evidence, etc. Each depth has its own feature space.
            Feat::SyntCallee { depth, .. } => match depth {
                1 => 16,
                2 => 8,
                3 => 4,
                _ => 2,
            },
        }
    }
}

fn fxhash<T: Hash>(t: T) -> u64 {
    let mut h = FxHasher::default();
    t.hash(&mut h);
    h.finish()
}

/// Constants outside this range are emitted as `Feat::Const`. Small values
/// (loop counters, struct offsets, alignment masks) appear in every function
/// and are useless for anchoring.
const CONST_NOISE_THRESHOLD: i64 = 256;

#[allow(clippy::too_many_arguments)]
fn extract_features(
    pe: &PeLoader,
    func: &FunctionAnalysis,
    iat: &HashMap<u64, String>,
    use_bigrams: bool,
    synth_map: Option<&FxHashMap<u64, u64>>,
    funcs_by_ep: Option<&FxHashMap<u64, &FunctionAnalysis>>,
    synt_depth: u8,
) -> FxHashSet<Feat> {
    let mut feats: FxHashSet<Feat> = FxHashSet::default();
    let bytes = match pe.read_at_va(func.entry_point, func.size) {
        Ok(b) => b,
        Err(_) => return feats,
    };
    let base = func.entry_point;

    for (&start, &end) in &func.basic_blocks {
        let off = (start - base) as usize;
        let end_off = (end - base) as usize;
        if end_off > bytes.len() || off >= end_off {
            continue;
        }
        let block = &bytes[off..end_off];
        let mut decoder = Decoder::with_ip(pe.bitness(), block, start, DecoderOptions::NONE);
        // Restart the bigram chain at each block boundary so we don't bridge
        // across control-flow joins.
        let mut prev: Option<(Mnemonic, [Option<OpKind>; 5])> = None;
        while decoder.can_decode() {
            let insn = decoder.decode();
            let mut ops: [Option<OpKind>; 5] = [None; 5];
            let n = (insn.op_count() as usize).min(5);
            for i in 0..n {
                ops[i] = Some(insn.op_kind(i as u32));
            }
            let cur = (insn.mnemonic(), ops);
            if use_bigrams && let Some(p) = prev {
                feats.insert(Feat::Bigram(fxhash((p, cur))));
            }
            prev = Some(cur);

            // Pull magic constants from immediate operands. These are largely
            // compiler-stable: cmp x, 0xdeadbeef compiles the same way under
            // MSVC and Clang.
            for i in 0..insn.op_count() {
                let v: Option<i64> = match insn.op_kind(i) {
                    OpKind::Immediate8 => Some(insn.immediate8() as i8 as i64),
                    OpKind::Immediate8_2nd => Some(insn.immediate8_2nd() as i8 as i64),
                    OpKind::Immediate16 => Some(insn.immediate16() as i16 as i64),
                    OpKind::Immediate32 => Some(insn.immediate32() as i32 as i64),
                    OpKind::Immediate64 => Some(insn.immediate64() as i64),
                    OpKind::Immediate8to16 => Some(insn.immediate8to16() as i64),
                    OpKind::Immediate8to32 => Some(insn.immediate8to32() as i64),
                    OpKind::Immediate8to64 => Some(insn.immediate8to64()),
                    OpKind::Immediate32to64 => Some(insn.immediate32to64()),
                    _ => None,
                };
                if let Some(v) = v
                    && v.unsigned_abs() as i64 > CONST_NOISE_THRESHOLD
                {
                    feats.insert(Feat::Const(v));
                }
            }
        }
    }

    let mut call_count: u32 = 0;
    for call in &func.calls {
        call_count += 1;
        if let Some(name) = iat.get(&call.target) {
            feats.insert(Feat::Import(fxhash(name)));
        } else if let Some(name) = pe.thunk_import(call.target, iat) {
            feats.insert(Feat::Import(fxhash(&name)));
        }
    }

    // Multi-hop SyntCallee: BFS callees up to `synt_depth` and emit a
    // depth-tagged synth feature for any callee whose pair was confirmed in
    // a prior pass. Depth-1 = direct callees (original behaviour). Higher
    // depths reach grandchildren etc., propagating identity signal further
    // per pass — at the cost of more features per signature and the risk
    // of hub explosion through nodes with high branching factor.
    if let Some(map) = synth_map
        && let Some(funcs_by_ep) = funcs_by_ep
    {
        let mut visited: FxHashSet<u64> = FxHashSet::default();
        visited.insert(func.entry_point);
        let mut queue: VecDeque<(u64, u8)> = VecDeque::new();
        for call in &func.calls {
            if iat.contains_key(&call.target) || pe.thunk_import(call.target, iat).is_some() {
                continue; // imports already handled
            }
            if visited.insert(call.target) {
                queue.push_back((call.target, 1));
            }
        }
        while let Some((node, depth)) = queue.pop_front() {
            if let Some(&s) = map.get(&node) {
                feats.insert(Feat::SyntCallee { depth, hash: s });
            }
            if depth < synt_depth
                && let Some(callee_func) = funcs_by_ep.get(&node)
            {
                // Hub gate: don't recurse through high-branching nodes.
                // Same threshold concept as bundling; hardcoded for now.
                if callee_func.calls.len() > 32 {
                    continue;
                }
                for c in &callee_func.calls {
                    if iat.contains_key(&c.target) {
                        continue;
                    }
                    if visited.insert(c.target) {
                        queue.push_back((c.target, depth + 1));
                    }
                }
            }
        }
    }

    for dref in &func.data_refs {
        if dref.is_readonly
            && dref.estimated_size.is_none()
            && let Some(s) = read_string_data(pe, dref.target)
        {
            feats.insert(Feat::StringLit(fxhash(&s)));
        }
    }

    feats.insert(Feat::BlockCountBucket(
        (func.basic_blocks.len() as u32).max(1).ilog2(),
    ));
    feats.insert(Feat::CallCountBucket((call_count + 1).ilog2()));

    feats
}

#[allow(clippy::too_many_arguments)]
fn build_graph(
    pe: &PeLoader,
    funcs: &[FunctionAnalysis],
    hasher: &UniversalMinHash,
    use_bigrams: bool,
    hops: usize,
    hub_degree: usize,
    bundle_dir: &str,
    bundle_filter: Option<&FxHashSet<&'static str>>,
    synth_map: Option<&FxHashMap<u64, u64>>,
    synt_depth: u8,
) -> Result<Graph<u64>> {
    use rayon::prelude::*;
    let iat = pe.iat()?;
    let func_set: FxHashSet<u64> = funcs.iter().map(|f| f.entry_point).collect();
    // Used by the multi-hop SyntCallee BFS in extract_features to recurse
    // through the call graph.
    let funcs_by_ep: FxHashMap<u64, &FunctionAnalysis> =
        funcs.iter().map(|f| (f.entry_point, f)).collect();

    // Per-function "own" features.
    let own: FxHashMap<u64, FxHashSet<Feat>> = funcs
        .par_iter()
        .map(|f| {
            (
                f.entry_point,
                extract_features(
                    pe,
                    f,
                    &iat,
                    use_bigrams,
                    synth_map,
                    Some(&funcs_by_ep),
                    synt_depth,
                ),
            )
        })
        .collect();

    // Build adjacency lists in both directions, restricted to functions in
    // our set.
    let mut callees: FxHashMap<u64, Vec<u64>> = FxHashMap::default();
    let mut callers: FxHashMap<u64, Vec<u64>> = FxHashMap::default();
    for func in funcs {
        for call in &func.calls {
            if call.target != func.entry_point && func_set.contains(&call.target) {
                callees
                    .entry(func.entry_point)
                    .or_default()
                    .push(call.target);
                callers
                    .entry(call.target)
                    .or_default()
                    .push(func.entry_point);
            }
        }
    }

    let dirs: &[&FxHashMap<u64, Vec<u64>>] = match bundle_dir {
        "callees" => &[&callees],
        "callers" => &[&callers],
        "both" => &[&callees, &callers],
        _ => unreachable!(),
    };

    // Bundle features from the k-hop neighborhood. The node's *own* features
    // stay as Feat::Bigram/Import/etc. Neighbor features are wrapped in
    // Feat::Nbr { depth, hash } so they live in a separate feature space —
    // matching on neighborhood is signal but doesn't masquerade as identity.
    let bundled: Vec<(u64, FxHashSet<Feat>)> = funcs
        .par_iter()
        .map(|f| {
            let start = f.entry_point;
            let mut feats: FxHashSet<Feat> = FxHashSet::default();
            // Own features go in unwrapped.
            if let Some(nf) = own.get(&start) {
                feats.extend(nf.iter().copied());
            }
            if hops == 0 {
                return (start, feats);
            }
            let mut visited: FxHashSet<u64> = FxHashSet::default();
            let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
            visited.insert(start);
            queue.push_back((start, 0));
            while let Some((node, depth)) = queue.pop_front() {
                if depth > 0 {
                    // Neighbor: wrap each of its features in Feat::Nbr,
                    // optionally filtering by category.
                    if let Some(nf) = own.get(&node) {
                        for nbr_feat in nf {
                            if let Some(allowed) = bundle_filter
                                && !allowed.contains(feat_category(nbr_feat))
                            {
                                continue;
                            }
                            feats.insert(Feat::Nbr {
                                depth: depth as u8,
                                hash: fxhash(nbr_feat),
                            });
                        }
                    }
                }
                if depth >= hops {
                    continue;
                }
                for adj in dirs {
                    if let Some(neighbors) = adj.get(&node) {
                        // Don't expand THROUGH a hub. We still consumed its
                        // own features when we popped it above.
                        if node != start && neighbors.len() > hub_degree {
                            continue;
                        }
                        for &n in neighbors {
                            if visited.insert(n) {
                                queue.push_back((n, depth + 1));
                            }
                        }
                    }
                }
            }
            (start, feats)
        })
        .collect();

    let mut counts: Vec<usize> = bundled.iter().map(|(_, s)| s.len()).collect();
    counts.sort_unstable();
    let pct = |p: f64| counts[((counts.len() as f64 * p) as usize).min(counts.len() - 1)];
    eprintln!(
        "  feature counts (hops={}): p50={} p90={} p99={} max={}",
        hops,
        pct(0.50),
        pct(0.90),
        pct(0.99),
        counts.last().copied().unwrap_or(0)
    );

    let mut g = Graph::default();
    g.add_nodes_par(bundled, hasher);
    for func in funcs {
        for call in &func.calls {
            if call.target != func.entry_point && func_set.contains(&call.target) {
                g.add_edge(func.entry_point, call.target);
            }
        }
    }
    Ok(g)
}

/// Load all function names from the PDB next to the given .exe. Each
/// address can have multiple names (public symbol = mangled ABI name,
/// module procedure = textual qualified name; sometimes COMDAT-folded
/// addresses have several aliases). We collect them all.
fn load_pdb_names(exe_path: &Path, pe: &PeLoader) -> Result<HashMap<u64, Vec<String>>> {
    let pdb_path = exe_path.with_extension("pdb");
    let source = MmapSource::new(&pdb_path)?;
    let mut pdb = PDB::open(source)?;
    let address_map = pdb.address_map()?;
    let image_base = pe.image_base();
    let mut names: HashMap<u64, Vec<String>> = HashMap::new();

    // Pass 1: public symbols (mangled).
    let global_symbols = pdb.global_symbols()?;
    let mut iter = global_symbols.iter();
    while let Ok(Some(symbol)) = iter.next() {
        if let Ok(SymbolData::Public(p)) = symbol.parse()
            && p.function
            && let Some(rva) = p.offset.to_rva(&address_map)
        {
            names
                .entry(image_base + rva.0 as u64)
                .or_default()
                .push(p.name.to_string().into_owned());
        }
    }

    // Pass 2: module-level procedure symbols (typically textual demangled).
    // For cross-compiler comparison these are the bridge — both MSVC and
    // Clang emit short qualified names here, which stem to compatible
    // identifiers even when their mangled forms diverge.
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    while let Ok(Some(module)) = modules.next() {
        let Ok(Some(module_info)) = pdb.module_info(&module) else {
            continue;
        };
        let Ok(mut symbols) = module_info.symbols() else {
            continue;
        };
        while let Ok(Some(sym)) = symbols.next() {
            if let Ok(SymbolData::Procedure(p)) = sym.parse()
                && let Some(rva) = p.offset.to_rva(&address_map)
            {
                names
                    .entry(image_base + rva.0 as u64)
                    .or_default()
                    .push(p.name.to_string().to_string());
            }
        }
    }

    // Dedup names per address.
    for v in names.values_mut() {
        v.sort();
        v.dedup();
    }
    Ok(names)
}

fn analyze(path: &PathBuf) -> Result<(PeLoader, Vec<FunctionAnalysis>)> {
    let pe = PeLoader::load(path)?;
    let warnings: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let funcs = pe.find_all_functions(&|m| warnings.lock().unwrap().push(m.into()))?;
    let warnings = warnings.into_inner().unwrap();
    if !warnings.is_empty() {
        eprintln!(
            "[{}] {} warnings during PE analysis",
            path.display(),
            warnings.len()
        );
    }
    Ok((pe, funcs))
}

/// Categorize a feature for per-bucket reporting.
fn feat_category(f: &Feat) -> &'static str {
    match f {
        Feat::Bigram(_) => "bigram",
        Feat::Import(_) => "import",
        Feat::StringLit(_) => "string",
        Feat::Const(_) => "const",
        Feat::BlockCountBucket(_) => "blkcount",
        Feat::CallCountBucket(_) => "callcount",
        Feat::Nbr { .. } => "nbr",
        Feat::SyntCallee { .. } => "synt",
    }
}

/// Resolve each call target to a human label. Imports get their API name;
/// internal calls get the first PDB name at that address; unresolved get a
/// raw address.
fn callee_labels(
    func: &FunctionAnalysis,
    pe: &PeLoader,
    iat: &HashMap<u64, String>,
    names: &HashMap<u64, Vec<String>>,
) -> Vec<String> {
    let mut out = Vec::new();
    for call in &func.calls {
        let label = if let Some(n) = iat.get(&call.target) {
            format!("import:{}", n)
        } else if let Some(n) = pe.thunk_import(call.target, iat) {
            format!("import:{}", n)
        } else if let Some(ns) = names.get(&call.target).and_then(|v| v.first()) {
            let trimmed = if ns.len() > 60 {
                &ns[..60]
            } else {
                ns.as_str()
            };
            format!("{}", trimmed)
        } else {
            format!("?{:#x}", call.target)
        };
        out.push(label);
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn report_pair(
    name: &str,
    addr_a: u64,
    addr_b: u64,
    func_a: &FunctionAnalysis,
    func_b: &FunctionAnalysis,
    feats_a: &FxHashSet<Feat>,
    feats_b: &FxHashSet<Feat>,
    alg_match: &FxHashMap<u64, u64>,
    alg_match_rev: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
    iat_a: &HashMap<u64, String>,
    iat_b: &HashMap<u64, String>,
    pe1: &PeLoader,
    pe2: &PeLoader,
    synth_a: Option<&FxHashMap<u64, u64>>,
    synth_b: Option<&FxHashMap<u64, u64>>,
) {
    let name_short = if name.len() > 78 {
        format!("{}…", &name[..78])
    } else {
        name.to_string()
    };

    let alg_b = alg_match.get(&addr_a).copied();
    let alg_str = match alg_b {
        None => "<no algorithm match>".to_string(),
        Some(b) if b == addr_b => "<correct>".to_string(),
        Some(b) => {
            let alg_names = names_b
                .get(&b)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let trim = if alg_names.len() > 64 {
                format!("{}…", &alg_names[..64])
            } else {
                alg_names
            };
            format!("{:#x} ({})", b, trim)
        }
    };

    println!();
    println!("# {}", name_short);
    println!(
        "#   base   {:#x} ({} bytes, {} blocks, {} calls)",
        addr_a,
        func_a.size,
        func_a.basic_blocks.len(),
        func_a.calls.len()
    );
    println!(
        "#   target {:#x} ({} bytes, {} blocks, {} calls)",
        addr_b,
        func_b.size,
        func_b.basic_blocks.len(),
        func_b.calls.len()
    );
    println!("#   algorithm: base → {}", alg_str);

    // Target's match status — was it claimed by another base addr?
    let target_status = match alg_match_rev.get(&addr_b).copied() {
        None => "<unmatched>".to_string(),
        Some(a) if a == addr_a => "<correct (paired with our base)>".to_string(),
        Some(a) => {
            let claim_name = names_a
                .get(&a)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let trim = if claim_name.len() > 64 {
                format!("{}…", &claim_name[..64])
            } else {
                claim_name
            };
            format!("claimed by base {:#x} ({})", a, trim)
        }
    };
    println!("#   target ← {}", target_status);

    // Callee lists side-by-side — directly visualizes inlining differences.
    // Annotate each callee with synth-status: ✓=both sides have synth IDs and
    // they're paired, △=both have IDs but different pairs, ·=at least one
    // side missing synth ID, ⌀=internal call but not in synth maps yet.
    let calls_a = callee_labels(func_a, pe1, iat_a, names_a);
    let calls_b = callee_labels(func_b, pe2, iat_b, names_b);
    let synth_marks_a: Vec<String> = func_a
        .calls
        .iter()
        .map(|c| match synth_a.and_then(|m| m.get(&c.target).copied()) {
            Some(s) => format!("S={}", s),
            None => "—".to_string(),
        })
        .collect();
    let synth_marks_b: Vec<String> = func_b
        .calls
        .iter()
        .map(|c| match synth_b.and_then(|m| m.get(&c.target).copied()) {
            Some(s) => format!("S={}", s),
            None => "—".to_string(),
        })
        .collect();
    let mut paired_synth_count = 0usize;
    let synth_a_set: FxHashSet<u64> = synth_marks_a
        .iter()
        .filter_map(|s| s.strip_prefix("S=").and_then(|n| n.parse().ok()))
        .collect();
    let synth_b_set: FxHashSet<u64> = synth_marks_b
        .iter()
        .filter_map(|s| s.strip_prefix("S=").and_then(|n| n.parse().ok()))
        .collect();
    for s in &synth_a_set {
        if synth_b_set.contains(s) {
            paired_synth_count += 1;
        }
    }
    let max = calls_a.len().max(calls_b.len());
    if max > 0 {
        println!(
            "#   callees: ({} synth IDs paired across sides)",
            paired_synth_count
        );
        for i in 0..max {
            let ca = calls_a.get(i).map(String::as_str).unwrap_or("");
            let cb = calls_b.get(i).map(String::as_str).unwrap_or("");
            let ca = if ca.len() > 46 { &ca[..46] } else { ca };
            let cb = if cb.len() > 46 { &cb[..46] } else { cb };
            let ma = synth_marks_a.get(i).map(String::as_str).unwrap_or("");
            let mb = synth_marks_b.get(i).map(String::as_str).unwrap_or("");
            println!("#     [{:<8}] {:<48} | [{:<8}] {}", ma, ca, mb, cb);
        }
    }

    // Per-category counts and intersection.
    let mut cats: std::collections::BTreeMap<&'static str, (FxHashSet<Feat>, FxHashSet<Feat>)> =
        Default::default();
    for f in feats_a {
        cats.entry(feat_category(f)).or_default().0.insert(*f);
    }
    for f in feats_b {
        cats.entry(feat_category(f)).or_default().1.insert(*f);
    }
    for (c, (sa, sb)) in &cats {
        let inter = sa.intersection(sb).count();
        let union = sa.union(sb).count();
        let jac = if union > 0 {
            inter as f64 / union as f64
        } else {
            0.0
        };
        println!(
            "#     {:>9}: a={:>5} b={:>5} ∩={:>5} ∪={:>5}  J={:.3}",
            c,
            sa.len(),
            sb.len(),
            inter,
            union,
            jac
        );
    }
    let inter_all = feats_a.intersection(feats_b).count();
    let union_all = feats_a.union(feats_b).count();
    let jac_all = if union_all > 0 {
        inter_all as f64 / union_all as f64
    } else {
        0.0
    };
    println!(
        "#     {:>9}: a={:>5} b={:>5} ∩={:>5} ∪={:>5}  J={:.3}",
        "TOTAL",
        feats_a.len(),
        feats_b.len(),
        inter_all,
        union_all,
        jac_all
    );

    // Weighted Jaccard — what the matcher actually approximates via MinHash.
    // This is what determines whether the pair clears the anchor threshold.
    // Note: this is OWN-only (no bundling); the matcher runs with bundling.
    // If hops>0 in the run, the actual matcher view is even richer than this.
    let w_a: u32 = feats_a.iter().map(|f| f.weight()).sum();
    let w_b: u32 = feats_b.iter().map(|f| f.weight()).sum();
    let w_inter: u32 = feats_a.intersection(feats_b).map(|f| f.weight()).sum();
    let w_union = w_a + w_b - w_inter;
    let w_jac = if w_union > 0 {
        w_inter as f64 / w_union as f64
    } else {
        0.0
    };
    println!(
        "#     {:>9}: a={:>5} b={:>5} ∩={:>5} ∪={:>5}  J={:.3}  (own-only, no bundling)",
        "WEIGHTED", w_a, w_b, w_inter, w_union, w_jac
    );

    // SyntCallee feature signal — what synth IDs would be added to this
    // function's feature set in the next iteration's signature. Both sides
    // emit Feat::SyntCallee(S) for any callee with a synth ID; if both sides
    // have callees with the SAME S, that's a free cross-binary anchor.
    if let (Some(sa), Some(sb)) = (synth_a, synth_b) {
        let mut a_ids: FxHashSet<u64> = FxHashSet::default();
        let mut b_ids: FxHashSet<u64> = FxHashSet::default();
        for c in &func_a.calls {
            if let Some(&s) = sa.get(&c.target) {
                a_ids.insert(s);
            }
        }
        for c in &func_b.calls {
            if let Some(&s) = sb.get(&c.target) {
                b_ids.insert(s);
            }
        }
        let shared = a_ids.intersection(&b_ids).count();
        println!(
            "#   synth-callee signal: a={} b={} shared={} (each shared = 1 weight-16 anchor on both sides)",
            a_ids.len(),
            b_ids.len(),
            shared
        );
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn inspect_patterns(
    patterns: &[String],
    limit: usize,
    sorted: &[(u64, u64)],
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
    funcs1: &[FunctionAnalysis],
    funcs2: &[FunctionAnalysis],
    pe1: &PeLoader,
    pe2: &PeLoader,
    use_bigrams: bool,
    synth_a: Option<&FxHashMap<u64, u64>>,
    synth_b: Option<&FxHashMap<u64, u64>>,
    synt_depth: u8,
) -> Result<()> {
    let mut by_name_a: FxHashMap<&str, Vec<u64>> = FxHashMap::default();
    for (addr, ns) in names_a {
        for s in ns {
            by_name_a.entry(s.as_str()).or_default().push(*addr);
        }
    }
    let mut by_name_b: FxHashMap<&str, Vec<u64>> = FxHashMap::default();
    for (addr, ns) in names_b {
        for s in ns {
            by_name_b.entry(s.as_str()).or_default().push(*addr);
        }
    }
    let alg_match: FxHashMap<u64, u64> = sorted.iter().copied().collect();
    let alg_match_rev: FxHashMap<u64, u64> = sorted.iter().map(|&(a, b)| (b, a)).collect();
    let funcs1_by_ep: FxHashMap<u64, &FunctionAnalysis> =
        funcs1.iter().map(|f| (f.entry_point, f)).collect();
    let funcs2_by_ep: FxHashMap<u64, &FunctionAnalysis> =
        funcs2.iter().map(|f| (f.entry_point, f)).collect();
    let iat_a = pe1.iat()?;
    let iat_b = pe2.iat()?;

    // Universe of names present in both binaries.
    for pat in patterns {
        // Find shared names containing this substring.
        let mut hits: Vec<&str> = by_name_a
            .keys()
            .copied()
            .filter(|n| n.contains(pat.as_str()) && by_name_b.contains_key(*n))
            .collect();
        hits.sort();
        hits.dedup();

        println!();
        println!(
            "# ============== pattern '{}' — {} matching shared names ==============",
            pat,
            hits.len()
        );
        for name in hits.iter().take(limit) {
            let addr_a = by_name_a[name][0];
            let addr_b = by_name_b[name][0];
            let (Some(&fa), Some(&fb)) = (funcs1_by_ep.get(&addr_a), funcs2_by_ep.get(&addr_b))
            else {
                continue;
            };
            let feats_a = extract_features(
                pe1,
                fa,
                &iat_a,
                use_bigrams,
                synth_a,
                Some(&funcs1_by_ep),
                synt_depth,
            );
            let feats_b = extract_features(
                pe2,
                fb,
                &iat_b,
                use_bigrams,
                synth_b,
                Some(&funcs2_by_ep),
                synt_depth,
            );
            report_pair(
                name,
                addr_a,
                addr_b,
                fa,
                fb,
                &feats_a,
                &feats_b,
                &alg_match,
                &alg_match_rev,
                names_a,
                names_b,
                &iat_a,
                &iat_b,
                pe1,
                pe2,
                synth_a,
                synth_b,
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn inspect_samples(
    n: usize,
    sorted: &[(u64, u64)],
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
    names_in_a: &FxHashSet<&str>,
    names_in_b: &FxHashSet<&str>,
    funcs1: &[FunctionAnalysis],
    funcs2: &[FunctionAnalysis],
    pe1: &PeLoader,
    pe2: &PeLoader,
    use_bigrams: bool,
    synth_a: Option<&FxHashMap<u64, u64>>,
    synth_b: Option<&FxHashMap<u64, u64>>,
    synt_depth: u8,
) -> Result<()> {
    // Build name → addrs maps.
    let mut by_name_a: FxHashMap<&str, Vec<u64>> = FxHashMap::default();
    for (addr, ns) in names_a {
        for s in ns {
            by_name_a.entry(s.as_str()).or_default().push(*addr);
        }
    }
    let mut by_name_b: FxHashMap<&str, Vec<u64>> = FxHashMap::default();
    for (addr, ns) in names_b {
        for s in ns {
            by_name_b.entry(s.as_str()).or_default().push(*addr);
        }
    }

    let alg_match: FxHashMap<u64, u64> = sorted.iter().copied().collect();
    let alg_match_rev: FxHashMap<u64, u64> = sorted.iter().map(|&(a, b)| (b, a)).collect();

    let funcs1_by_ep: FxHashMap<u64, &FunctionAnalysis> =
        funcs1.iter().map(|f| (f.entry_point, f)).collect();
    let funcs2_by_ep: FxHashMap<u64, &FunctionAnalysis> =
        funcs2.iter().map(|f| (f.entry_point, f)).collect();

    let iat_a = pe1.iat()?;
    let iat_b = pe2.iat()?;

    // Walk shared names; for each, take the canonical (first-addr, first-addr)
    // pair and bucket into TP / FN cohorts.
    let mut tp_pool: Vec<(&str, u64, u64)> = Vec::new();
    let mut fn_pool: Vec<(&str, u64, u64)> = Vec::new();

    for &name in names_in_a.iter() {
        if !names_in_b.contains(name) {
            continue;
        }
        let Some(a_addrs) = by_name_a.get(name) else {
            continue;
        };
        let Some(b_addrs) = by_name_b.get(name) else {
            continue;
        };
        let addr_a = a_addrs[0];
        let addr_b = b_addrs[0];
        if !funcs1_by_ep.contains_key(&addr_a) || !funcs2_by_ep.contains_key(&addr_b) {
            continue;
        }
        if alg_match.get(&addr_a).copied() == Some(addr_b) {
            tp_pool.push((name, addr_a, addr_b));
        } else {
            fn_pool.push((name, addr_a, addr_b));
        }
    }

    // Stable sort to get deterministic samples across runs.
    tp_pool.sort_by_key(|&(_, a, _)| a);
    fn_pool.sort_by_key(|&(_, a, _)| a);

    let stride_pick = |pool: &[(&str, u64, u64)], k: usize| -> Vec<(String, u64, u64)> {
        if pool.is_empty() || k == 0 {
            return Vec::new();
        }
        let k = k.min(pool.len());
        let stride = pool.len() / k;
        (0..k)
            .map(|i| {
                let (s, a, b) = pool[i * stride];
                (s.to_string(), a, b)
            })
            .collect()
    };

    println!();
    println!(
        "# === inspect: TP cohort size {}, FN cohort size {} ===",
        tp_pool.len(),
        fn_pool.len()
    );

    let dump = |label: &str, samples: &[(String, u64, u64)]| {
        println!();
        println!("# --- {} ({} samples) ---", label, samples.len());
        for (name, addr_a, addr_b) in samples {
            let func_a = funcs1_by_ep[addr_a];
            let func_b = funcs2_by_ep[addr_b];
            let feats_a = extract_features(
                pe1,
                func_a,
                &iat_a,
                use_bigrams,
                synth_a,
                Some(&funcs1_by_ep),
                synt_depth,
            );
            let feats_b = extract_features(
                pe2,
                func_b,
                &iat_b,
                use_bigrams,
                synth_b,
                Some(&funcs2_by_ep),
                synt_depth,
            );
            report_pair(
                name,
                *addr_a,
                *addr_b,
                func_a,
                func_b,
                &feats_a,
                &feats_b,
                &alg_match,
                &alg_match_rev,
                names_a,
                names_b,
                &iat_a,
                &iat_b,
                pe1,
                pe2,
                synth_a,
                synth_b,
            );
        }
    };

    let tp_samples = stride_pick(&tp_pool, n);
    let fn_samples = stride_pick(&fn_pool, n);
    dump("TP (algorithm matched correctly)", &tp_samples);
    dump("FN (same name in both, algorithm missed)", &fn_samples);

    Ok(())
}

struct PdbContext {
    names_a: HashMap<u64, Vec<String>>,
    names_b: HashMap<u64, Vec<String>>,
    baseline_addrs: usize,
}

struct RunResult {
    sorted: Vec<(u64, u64)>,
    synth_a: FxHashMap<u64, u64>,
    synth_b: FxHashMap<u64, u64>,
    matched: usize,
    valid: usize,
    tp: usize,
    precision: f64,
    recall: f64,
    time_secs: f64,
    disagree_examples: Vec<(String, String)>,
}

#[allow(clippy::too_many_arguments)]
fn run_match(
    args: &Args,
    pe1: &PeLoader,
    funcs1: &[FunctionAnalysis],
    pe2: &PeLoader,
    funcs2: &[FunctionAnalysis],
    pdb: Option<&PdbContext>,
    quiet: bool,
) -> Result<RunResult> {
    let start = std::time::Instant::now();

    let config = MatcherConfig {
        k_permutations: args.k,
        lsh_bands: args.bands,
        min_features_for_lsh: args.min_features,
        anchor_threshold: args.anchor,
        propagation_threshold: args.propagate,
        max_propagation_degree: args.max_degree,
        size_mismatch_ratio: 2.0,
        pre_match_on_identifiers: false,
        min_band_collisions: args.min_band_collisions,
    };
    let hasher = config.hasher(args.seed);
    let use_bigrams = !args.no_bigrams;

    static CATEGORIES: &[&str] = &[
        "bigram",
        "import",
        "string",
        "const",
        "blkcount",
        "callcount",
    ];
    let bundle_filter: Option<FxHashSet<&'static str>> = args.bundle_features.as_ref().map(|v| {
        v.iter()
            .map(|s| {
                CATEGORIES
                    .iter()
                    .copied()
                    .find(|c| *c == s.as_str())
                    .unwrap_or_else(|| {
                        panic!(
                            "unknown --bundle-features category '{}'. Allowed: {:?}",
                            s, CATEGORIES
                        )
                    })
            })
            .collect()
    });

    let mut synth_a: FxHashMap<u64, u64> = FxHashMap::default();
    let mut synth_b: FxHashMap<u64, u64> = FxHashMap::default();
    let mut next_synth_id: u64 = 0;
    let mut matches: FxHashMap<u64, u64> = FxHashMap::default();

    let mut last_precision = 0.0;
    let mut last_recall = 0.0;
    let mut last_valid = 0usize;
    let mut last_tp = 0usize;

    let total_passes = args.iterations.max(1);
    for pass in 0..total_passes {
        let synth_a_ref = if synth_a.is_empty() {
            None
        } else {
            Some(&synth_a)
        };
        let synth_b_ref = if synth_b.is_empty() {
            None
        } else {
            Some(&synth_b)
        };

        if !quiet {
            eprintln!(
                "pass {}/{}: building graphs (bigrams={}, hops={}, bundle_filter={:?}, synth={})",
                pass + 1,
                total_passes,
                if use_bigrams { "on" } else { "off" },
                args.hops,
                bundle_filter,
                synth_a.len(),
            );
        }
        let g1 = build_graph(
            pe1,
            funcs1,
            &hasher,
            use_bigrams,
            args.hops,
            args.hub_degree,
            &args.bundle,
            bundle_filter.as_ref(),
            synth_a_ref,
            args.synt_depth,
        )?;
        let g2 = build_graph(
            pe2,
            funcs2,
            &hasher,
            use_bigrams,
            args.hops,
            args.hub_degree,
            &args.bundle,
            bundle_filter.as_ref(),
            synth_b_ref,
            args.synt_depth,
        )?;

        if !quiet {
            eprintln!("pass {}/{}: matching", pass + 1, total_passes);
        }
        let new_matches = config.run(&g1, &g2);

        let mut new_pair_count = 0usize;
        for (&a, &b) in &new_matches {
            if synth_a.contains_key(&a) || synth_b.contains_key(&b) {
                continue;
            }
            let s = next_synth_id;
            next_synth_id += 1;
            synth_a.insert(a, s);
            synth_b.insert(b, s);
            new_pair_count += 1;
        }
        if !quiet {
            eprintln!(
                "  pass {}: {} matches total, {} new pairs assigned synth IDs (synth pool: {})",
                pass + 1,
                new_matches.len(),
                new_pair_count,
                synth_a.len()
            );
        }

        if let Some(pdb) = pdb {
            let sets_a: HashMap<u64, FxHashSet<&str>> = pdb
                .names_a
                .iter()
                .map(|(&addr, ns)| (addr, ns.iter().map(String::as_str).collect()))
                .collect();
            let sets_b: HashMap<u64, FxHashSet<&str>> = pdb
                .names_b
                .iter()
                .map(|(&addr, ns)| (addr, ns.iter().map(String::as_str).collect()))
                .collect();
            let mut both_named = 0usize;
            let mut tp = 0usize;
            for (a, b) in &new_matches {
                if let (Some(sa), Some(sb)) = (sets_a.get(a), sets_b.get(b)) {
                    if sa.is_empty() || sb.is_empty() {
                        continue;
                    }
                    both_named += 1;
                    if sa.iter().any(|n| sb.contains(n)) {
                        tp += 1;
                    }
                }
            }
            let precision = tp as f64 / both_named.max(1) as f64;
            let recall = tp as f64 / pdb.baseline_addrs.max(1) as f64;
            if !quiet {
                println!(
                    "# pass {}/{}: matched={} valid={} prec={:.2}% recall={:.2}%",
                    pass + 1,
                    total_passes,
                    new_matches.len(),
                    both_named,
                    precision * 100.0,
                    recall * 100.0,
                );
            }
            last_precision = precision;
            last_recall = recall;
            last_valid = both_named;
            last_tp = tp;
        }

        matches = new_matches;
    }

    let mut sorted: Vec<(u64, u64)> = matches.into_iter().collect();
    sorted.sort_unstable();

    let mut disagree_examples: Vec<(String, String)> = Vec::new();
    if let Some(pdb) = pdb {
        let sets_a: HashMap<u64, FxHashSet<&str>> = pdb
            .names_a
            .iter()
            .map(|(&addr, ns)| (addr, ns.iter().map(String::as_str).collect()))
            .collect();
        let sets_b: HashMap<u64, FxHashSet<&str>> = pdb
            .names_b
            .iter()
            .map(|(&addr, ns)| (addr, ns.iter().map(String::as_str).collect()))
            .collect();
        for (a, b) in &sorted {
            if disagree_examples.len() >= 10 {
                break;
            }
            if let (Some(sa), Some(sb)) = (sets_a.get(a), sets_b.get(b)) {
                if sa.is_empty() || sb.is_empty() {
                    continue;
                }
                if !sa.iter().any(|n| sb.contains(n)) {
                    let na = pdb
                        .names_a
                        .get(a)
                        .and_then(|v| v.first())
                        .cloned()
                        .unwrap_or_default();
                    let nb = pdb
                        .names_b
                        .get(b)
                        .and_then(|v| v.first())
                        .cloned()
                        .unwrap_or_default();
                    disagree_examples.push((na, nb));
                }
            }
        }
    }

    let time_secs = start.elapsed().as_secs_f64();

    Ok(RunResult {
        matched: sorted.len(),
        sorted,
        synth_a,
        synth_b,
        valid: last_valid,
        tp: last_tp,
        precision: last_precision,
        recall: last_recall,
        time_secs,
        disagree_examples,
    })
}

fn write_matches_cache(path: &Path, args: &Args, result: &RunResult) -> Result<()> {
    use std::fmt::Write as _;
    let mut s = String::new();
    writeln!(s, "# binfold graph-diff matches cache v1").unwrap();
    writeln!(s, "[meta]").unwrap();
    writeln!(s, "base_exe\t{}", args.base.display()).unwrap();
    writeln!(s, "target_exe\t{}", args.target.display()).unwrap();
    writeln!(s, "matched\t{}", result.matched).unwrap();
    writeln!(s, "[matches]").unwrap();
    for (a, b) in &result.sorted {
        writeln!(s, "{:#x}\t{:#x}", a, b).unwrap();
    }
    let mut dump = |label: &str, m: &FxHashMap<u64, u64>| {
        writeln!(s, "[{}]", label).unwrap();
        let mut sorted: Vec<(&u64, &u64)> = m.iter().collect();
        sorted.sort_unstable_by_key(|(k, _)| *k);
        for (k, v) in sorted {
            writeln!(s, "{:#x}\t{}", k, v).unwrap();
        }
    };
    dump("synth_a", &result.synth_a);
    dump("synth_b", &result.synth_b);
    std::fs::write(path, s)?;
    Ok(())
}

fn load_pdb_context(args: &Args, pe1: &PeLoader, pe2: &PeLoader) -> Result<PdbContext> {
    let names_a = load_pdb_names(&args.base, pe1)?;
    let names_b = load_pdb_names(&args.target, pe2)?;
    let names_in_a: FxHashSet<&str> = names_a.values().flatten().map(String::as_str).collect();
    let names_in_b: FxHashSet<&str> = names_b.values().flatten().map(String::as_str).collect();
    let shared: usize = names_in_a
        .iter()
        .filter(|n| names_in_b.contains(*n))
        .count();
    let baseline_addrs: usize = names_a
        .iter()
        .filter(|(_, ns)| ns.iter().any(|n| names_in_b.contains(n.as_str())))
        .count();
    eprintln!(
        "  base PDB: {} addrs / {} unique names. target: {} addrs / {} unique names",
        names_a.len(),
        names_in_a.len(),
        names_b.len(),
        names_in_b.len(),
    );
    println!("# baseline:");
    println!(
        "#   names present in BOTH binaries: {} ({:.1}% of base, {:.1}% of target)",
        shared,
        shared as f64 / names_in_a.len().max(1) as f64 * 100.0,
        shared as f64 / names_in_b.len().max(1) as f64 * 100.0,
    );
    println!(
        "#   base addrs with any name present in target: {} ({:.1}% of {} base addrs with names)",
        baseline_addrs,
        baseline_addrs as f64 / names_a.len().max(1) as f64 * 100.0,
        names_a.len(),
    );
    Ok(PdbContext {
        names_a,
        names_b,
        baseline_addrs,
    })
}

fn run_sweep(
    base_args: &Args,
    pe1: &PeLoader,
    funcs1: &[FunctionAnalysis],
    pe2: &PeLoader,
    funcs2: &[FunctionAnalysis],
    pdb: &PdbContext,
) -> Result<()> {
    type Mut = Box<dyn Fn(&mut Args)>;
    let groups: Vec<(&'static str, Vec<(&'static str, Mut)>)> = vec![
        (
            "k (bands tracks K, rows≈8)",
            vec![
                (
                    "k=200 bands=25",
                    Box::new(|a: &mut Args| {
                        a.k = 200;
                        a.bands = 25;
                    }),
                ),
                (
                    "k=400 bands=50",
                    Box::new(|a: &mut Args| {
                        a.k = 400;
                        a.bands = 50;
                    }),
                ),
                (
                    "k=1200 bands=150",
                    Box::new(|a: &mut Args| {
                        a.k = 1200;
                        a.bands = 150;
                    }),
                ),
                (
                    "k=1600 bands=200",
                    Box::new(|a: &mut Args| {
                        a.k = 1600;
                        a.bands = 200;
                    }),
                ),
            ],
        ),
        (
            "bands at fixed K (rows-per-band)",
            vec![
                ("bands=50 (rows≈16)", Box::new(|a: &mut Args| a.bands = 50)),
                ("bands=200 (rows≈4)", Box::new(|a: &mut Args| a.bands = 200)),
            ],
        ),
        (
            "anchor threshold",
            vec![
                ("anchor=0.3", Box::new(|a: &mut Args| a.anchor = 0.3)),
                ("anchor=0.4", Box::new(|a: &mut Args| a.anchor = 0.4)),
                ("anchor=0.6", Box::new(|a: &mut Args| a.anchor = 0.6)),
                ("anchor=0.7", Box::new(|a: &mut Args| a.anchor = 0.7)),
            ],
        ),
        (
            "propagate threshold",
            vec![
                (
                    "propagate=0.05",
                    Box::new(|a: &mut Args| a.propagate = 0.05),
                ),
                ("propagate=0.1", Box::new(|a: &mut Args| a.propagate = 0.1)),
                ("propagate=0.3", Box::new(|a: &mut Args| a.propagate = 0.3)),
                ("propagate=0.4", Box::new(|a: &mut Args| a.propagate = 0.4)),
            ],
        ),
        (
            "max-degree (Phase 4 hub gate)",
            vec![
                ("max-degree=16", Box::new(|a: &mut Args| a.max_degree = 16)),
                ("max-degree=32", Box::new(|a: &mut Args| a.max_degree = 32)),
                (
                    "max-degree=128",
                    Box::new(|a: &mut Args| a.max_degree = 128),
                ),
                (
                    "max-degree=256",
                    Box::new(|a: &mut Args| a.max_degree = 256),
                ),
            ],
        ),
        (
            "min-features",
            vec![
                (
                    "min-features=2",
                    Box::new(|a: &mut Args| a.min_features = 2),
                ),
                (
                    "min-features=8",
                    Box::new(|a: &mut Args| a.min_features = 8),
                ),
                (
                    "min-features=16",
                    Box::new(|a: &mut Args| a.min_features = 16),
                ),
                (
                    "min-features=32",
                    Box::new(|a: &mut Args| a.min_features = 32),
                ),
            ],
        ),
        (
            "hops (bundling depth)",
            vec![
                ("hops=0", Box::new(|a: &mut Args| a.hops = 0)),
                ("hops=1", Box::new(|a: &mut Args| a.hops = 1)),
                ("hops=3", Box::new(|a: &mut Args| a.hops = 3)),
            ],
        ),
        (
            "hub-degree (bundling hub gate)",
            vec![
                ("hub-degree=8", Box::new(|a: &mut Args| a.hub_degree = 8)),
                ("hub-degree=16", Box::new(|a: &mut Args| a.hub_degree = 16)),
                ("hub-degree=64", Box::new(|a: &mut Args| a.hub_degree = 64)),
                (
                    "hub-degree=128",
                    Box::new(|a: &mut Args| a.hub_degree = 128),
                ),
            ],
        ),
        (
            "bundle direction",
            vec![
                (
                    "bundle=callees",
                    Box::new(|a: &mut Args| a.bundle = "callees".to_string()),
                ),
                (
                    "bundle=callers",
                    Box::new(|a: &mut Args| a.bundle = "callers".to_string()),
                ),
            ],
        ),
        (
            "bundle-features",
            vec![
                (
                    "(all categories propagate)",
                    Box::new(|a: &mut Args| a.bundle_features = None),
                ),
                (
                    "import,string",
                    Box::new(|a: &mut Args| {
                        a.bundle_features = Some(vec!["import".into(), "string".into()])
                    }),
                ),
                (
                    "string only",
                    Box::new(|a: &mut Args| a.bundle_features = Some(vec!["string".into()])),
                ),
                (
                    "import,string,const,callcount,blkcount",
                    Box::new(|a: &mut Args| {
                        a.bundle_features = Some(vec![
                            "import".into(),
                            "string".into(),
                            "const".into(),
                            "callcount".into(),
                            "blkcount".into(),
                        ])
                    }),
                ),
            ],
        ),
        (
            "bigrams",
            vec![("--no-bigrams", Box::new(|a: &mut Args| a.no_bigrams = true))],
        ),
        (
            "iterations",
            vec![
                ("iterations=1", Box::new(|a: &mut Args| a.iterations = 1)),
                ("iterations=2", Box::new(|a: &mut Args| a.iterations = 2)),
                ("iterations=4", Box::new(|a: &mut Args| a.iterations = 4)),
                ("iterations=5", Box::new(|a: &mut Args| a.iterations = 5)),
            ],
        ),
    ];

    let total_runs: usize = 1 + groups.iter().map(|(_, vs)| vs.len()).sum::<usize>();

    println!();
    println!(
        "# === sweep: OAT perturbation ({} runs, ~{:.0}-{:.0} min estimated) ===",
        total_runs,
        total_runs as f64 * 25.0 / 60.0,
        total_runs as f64 * 45.0 / 60.0,
    );
    eprintln!("[sweep 1/{}] running baseline...", total_runs);
    let baseline = run_match(base_args, pe1, funcs1, pe2, funcs2, Some(pdb), true)?;
    println!();
    println!(
        "# baseline: prec={:.2}%  recall={:.2}%  matched={}  valid={}  time={:.1}s",
        baseline.precision * 100.0,
        baseline.recall * 100.0,
        baseline.matched,
        baseline.valid,
        baseline.time_secs
    );

    let mut run_idx = 1usize;
    for (group_name, variations) in &groups {
        println!();
        println!("# === {} ===", group_name);
        println!(
            "# {:<42} {:>7} {:>7} {:>9} {:>8} {:>7}   {}",
            "config", "prec", "recall", "matched", "valid", "time", "Δ vs baseline"
        );
        println!(
            "# {:<42} {:>6.2}% {:>6.2}% {:>9} {:>8} {:>6.1}s   (baseline)",
            "[baseline]",
            baseline.precision * 100.0,
            baseline.recall * 100.0,
            baseline.matched,
            baseline.valid,
            baseline.time_secs,
        );
        for (label, mutate) in variations {
            run_idx += 1;
            eprintln!(
                "[sweep {}/{}] {}: {} ...",
                run_idx, total_runs, group_name, label
            );
            let mut a = base_args.clone();
            mutate(&mut a);
            let r = match run_match(&a, pe1, funcs1, pe2, funcs2, Some(pdb), true) {
                Ok(r) => r,
                Err(e) => {
                    println!("# {:<42} ERROR: {}", label, e);
                    continue;
                }
            };
            let dp = (r.precision - baseline.precision) * 100.0;
            let dr = (r.recall - baseline.recall) * 100.0;
            println!(
                "# {:<42} {:>6.2}% {:>6.2}% {:>9} {:>8} {:>6.1}s   Δprec={:+.2}pp Δrecall={:+.2}pp",
                label,
                r.precision * 100.0,
                r.recall * 100.0,
                r.matched,
                r.valid,
                r.time_secs,
                dp,
                dr,
            );
        }
    }

    println!();
    println!(
        "# sweep done. baseline: prec={:.2}% recall={:.2}%",
        baseline.precision * 100.0,
        baseline.recall * 100.0
    );
    Ok(())
}

fn run_sweep_combos(
    base_args: &Args,
    pe1: &PeLoader,
    funcs1: &[FunctionAnalysis],
    pe2: &PeLoader,
    funcs2: &[FunctionAnalysis],
    pdb: &PdbContext,
) -> Result<()> {
    type Mut = Box<dyn Fn(&mut Args)>;
    // Combinations of OAT-identified levers. Each tests whether the
    // independent perturbations stack additively or saturate when combined.
    // Categories:
    //  - "stack precision-positives": bands=50, max-degree=32, min-features=32
    //  - "trade prec for recall": add bundle shape categories or anchor=0.6
    //  - "max-precision push": stack + raise anchor
    //  - "max-recall push": loosen bands, drop bigrams
    let combos: Vec<(&'static str, Mut)> = vec![
        (
            "bands=50 + min-features=32",
            Box::new(|a: &mut Args| {
                a.bands = 50;
                a.min_features = 32;
            }),
        ),
        (
            "bands=50 + max-degree=32",
            Box::new(|a: &mut Args| {
                a.bands = 50;
                a.max_degree = 32;
            }),
        ),
        (
            "min-features=32 + max-degree=32",
            Box::new(|a: &mut Args| {
                a.min_features = 32;
                a.max_degree = 32;
            }),
        ),
        (
            "bands=50 + min-features=32 + max-degree=32",
            Box::new(|a: &mut Args| {
                a.bands = 50;
                a.min_features = 32;
                a.max_degree = 32;
            }),
        ),
        (
            "triple stack + anchor=0.6",
            Box::new(|a: &mut Args| {
                a.bands = 50;
                a.min_features = 32;
                a.max_degree = 32;
                a.anchor = 0.6;
            }),
        ),
        (
            "triple stack + anchor=0.7",
            Box::new(|a: &mut Args| {
                a.bands = 50;
                a.min_features = 32;
                a.max_degree = 32;
                a.anchor = 0.7;
            }),
        ),
        (
            "triple stack + bundle+callcount,blkcount",
            Box::new(|a: &mut Args| {
                a.bands = 50;
                a.min_features = 32;
                a.max_degree = 32;
                a.bundle_features = Some(vec![
                    "import".into(),
                    "string".into(),
                    "const".into(),
                    "callcount".into(),
                    "blkcount".into(),
                ]);
            }),
        ),
        (
            "min-features=32 + bundle+callcount,blkcount",
            Box::new(|a: &mut Args| {
                a.min_features = 32;
                a.bundle_features = Some(vec![
                    "import".into(),
                    "string".into(),
                    "const".into(),
                    "callcount".into(),
                    "blkcount".into(),
                ]);
            }),
        ),
        (
            "bundle+callcount,blkcount + max-degree=128",
            Box::new(|a: &mut Args| {
                a.bundle_features = Some(vec![
                    "import".into(),
                    "string".into(),
                    "const".into(),
                    "callcount".into(),
                    "blkcount".into(),
                ]);
                a.max_degree = 128;
            }),
        ),
        (
            "max-recall push: bands=200 + bundle+callcount,blkcount",
            Box::new(|a: &mut Args| {
                a.bands = 200;
                a.bundle_features = Some(vec![
                    "import".into(),
                    "string".into(),
                    "const".into(),
                    "callcount".into(),
                    "blkcount".into(),
                ]);
            }),
        ),
        (
            "max-recall push: --no-bigrams + bundle+callcount,blkcount",
            Box::new(|a: &mut Args| {
                a.no_bigrams = true;
                a.bundle_features = Some(vec![
                    "import".into(),
                    "string".into(),
                    "const".into(),
                    "callcount".into(),
                    "blkcount".into(),
                ]);
            }),
        ),
    ];

    let total_runs = 1 + combos.len();

    println!();
    println!(
        "# === sweep-combos: {} combinations of OAT-identified levers ===",
        combos.len()
    );
    eprintln!("[combos 1/{}] running baseline...", total_runs);
    let baseline = run_match(base_args, pe1, funcs1, pe2, funcs2, Some(pdb), true)?;
    println!();
    println!(
        "# baseline: prec={:.2}%  recall={:.2}%  matched={}  valid={}  time={:.1}s",
        baseline.precision * 100.0,
        baseline.recall * 100.0,
        baseline.matched,
        baseline.valid,
        baseline.time_secs
    );
    println!();
    println!(
        "# {:<58} {:>7} {:>7} {:>9} {:>8} {:>7}   {}",
        "config", "prec", "recall", "matched", "valid", "time", "Δ vs baseline"
    );
    println!(
        "# {:<58} {:>6.2}% {:>6.2}% {:>9} {:>8} {:>6.1}s   (baseline)",
        "[baseline]",
        baseline.precision * 100.0,
        baseline.recall * 100.0,
        baseline.matched,
        baseline.valid,
        baseline.time_secs,
    );

    let mut idx = 1usize;
    for (label, mutate) in &combos {
        idx += 1;
        eprintln!("[combos {}/{}] {} ...", idx, total_runs, label);
        let mut a = base_args.clone();
        mutate(&mut a);
        let r = match run_match(&a, pe1, funcs1, pe2, funcs2, Some(pdb), true) {
            Ok(r) => r,
            Err(e) => {
                println!("# {:<58} ERROR: {}", label, e);
                continue;
            }
        };
        let dp = (r.precision - baseline.precision) * 100.0;
        let dr = (r.recall - baseline.recall) * 100.0;
        println!(
            "# {:<58} {:>6.2}% {:>6.2}% {:>9} {:>8} {:>6.1}s   Δprec={:+.2}pp Δrecall={:+.2}pp",
            label,
            r.precision * 100.0,
            r.recall * 100.0,
            r.matched,
            r.valid,
            r.time_secs,
            dp,
            dr,
        );
    }

    println!();
    println!(
        "# combos done. baseline: prec={:.2}% recall={:.2}%",
        baseline.precision * 100.0,
        baseline.recall * 100.0
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let t = std::time::Instant::now();
    let mut last = t;
    let mut tick = |label: &str| {
        let now = std::time::Instant::now();
        eprintln!(
            "[{:>6.1}s +{:>5.1}s] {}",
            (now - t).as_secs_f64(),
            (now - last).as_secs_f64(),
            label
        );
        last = now;
    };

    tick(&format!("loading {}", args.base.display()));
    let (pe1, funcs1) = analyze(&args.base)?;
    tick(&format!("  {} functions", funcs1.len()));

    tick(&format!("loading {}", args.target.display()));
    let (pe2, funcs2) = analyze(&args.target)?;
    tick(&format!("  {} functions", funcs2.len()));

    let need_pdb = args.validate || args.sweep || args.sweep_combos;
    let pdb_ctx: Option<PdbContext> = if need_pdb {
        tick("loading PDBs");
        Some(load_pdb_context(&args, &pe1, &pe2)?)
    } else {
        None
    };

    if args.sweep {
        return run_sweep(
            &args,
            &pe1,
            &funcs1,
            &pe2,
            &funcs2,
            pdb_ctx.as_ref().expect("sweep requires PDBs"),
        );
    }
    if args.sweep_combos {
        return run_sweep_combos(
            &args,
            &pe1,
            &funcs1,
            &pe2,
            &funcs2,
            pdb_ctx.as_ref().expect("sweep-combos requires PDBs"),
        );
    }

    let result = run_match(&args, &pe1, &funcs1, &pe2, &funcs2, pdb_ctx.as_ref(), false)?;
    tick("matching done");

    if let Some(path) = &args.emit_matches {
        write_matches_cache(path, &args, &result)?;
        tick(&format!("wrote matches cache to {}", path.display()));
    }

    println!(
        "# matched {} / {} base functions",
        result.matched,
        funcs1.len()
    );

    if let Some(pdb) = &pdb_ctx {
        println!("# matches:");
        println!(
            "#   algorithm matched {} / {} base functions",
            result.matched,
            funcs1.len()
        );
        println!(
            "#   of matches, {} have PDB names on BOTH sides (validatable)",
            result.valid
        );
        println!(
            "#   precision (any-name overlap): {} / {} = {:.2}%",
            result.tp,
            result.valid,
            result.precision * 100.0
        );
        println!(
            "#   recall vs baseline:           {} / {} = {:.2}%",
            result.tp,
            pdb.baseline_addrs,
            result.recall * 100.0
        );
        if !result.disagree_examples.is_empty() {
            println!("# example disagreements (first name shown each side):");
            for (na, nb) in &result.disagree_examples {
                let na = if na.len() > 80 {
                    &na[..80]
                } else {
                    na.as_str()
                };
                let nb = if nb.len() > 80 {
                    &nb[..80]
                } else {
                    nb.as_str()
                };
                println!("#   {}\n# ≠ {}", na, nb);
            }
        }

        let names_in_a: FxHashSet<&str> =
            pdb.names_a.values().flatten().map(String::as_str).collect();
        let names_in_b: FxHashSet<&str> =
            pdb.names_b.values().flatten().map(String::as_str).collect();
        let synth_a_ref = if result.synth_a.is_empty() {
            None
        } else {
            Some(&result.synth_a)
        };
        let synth_b_ref = if result.synth_b.is_empty() {
            None
        } else {
            Some(&result.synth_b)
        };
        if args.inspect_samples > 0 {
            inspect_samples(
                args.inspect_samples,
                &result.sorted,
                &pdb.names_a,
                &pdb.names_b,
                &names_in_a,
                &names_in_b,
                &funcs1,
                &funcs2,
                &pe1,
                &pe2,
                !args.no_bigrams,
                synth_a_ref,
                synth_b_ref,
                args.synt_depth,
            )?;
        }

        if !args.inspect_patterns.is_empty() {
            inspect_patterns(
                &args.inspect_patterns,
                args.inspect_pattern_limit,
                &result.sorted,
                &pdb.names_a,
                &pdb.names_b,
                &funcs1,
                &funcs2,
                &pe1,
                &pe2,
                !args.no_bigrams,
                synth_a_ref,
                synth_b_ref,
                args.synt_depth,
            )?;
        }
    }

    println!("# {:>16} -> {:>16}", "base", "target");
    for (a, b) in result.sorted.iter().take(args.limit) {
        println!("{:#018x} -> {:#018x}", a, b);
    }
    if result.sorted.len() > args.limit {
        println!("... ({} more)", result.sorted.len() - args.limit);
    }

    Ok(())
}
