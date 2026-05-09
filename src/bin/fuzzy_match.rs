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

#[derive(Parser)]
#[command(about = "Fuzzy-match functions between two PEs using grapnel")]
struct Args {
    base: PathBuf,
    target: PathBuf,

    #[arg(long, default_value_t = 200)]
    k: usize,
    /// Number of LSH bands. With K=200, defaults to 25 (8 rows/band → ~0.69
    /// effective threshold). Increase to lower threshold (more candidates).
    #[arg(long, default_value_t = 25)]
    bands: usize,
    /// Minimum total feature weight for a node to enter the LSH index. Higher
    /// values exclude trivial thunks/getters from anchoring (propagation
    /// handles them) and dramatically shrinks candidate lists on UE binaries.
    #[arg(long, default_value_t = 16)]
    min_features: u32,
    #[arg(long, default_value_t = 0.72)]
    anchor: f64,
    #[arg(long, default_value_t = 0.48)]
    propagate: f64,
    #[arg(long, default_value_t = 16)]
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
    /// each node's signature. 0 = no bundling. Higher = more topological
    /// context (helps anchor leaf functions via their callers' strings).
    #[arg(long, default_value_t = 0)]
    hops: usize,

    /// When bundling, skip expansion through any node with more incoming or
    /// outgoing edges than this. Prevents hub functions (memcpy, log,
    /// allocator wrappers) from polluting every neighborhood.
    #[arg(long, default_value_t = 32)]
    hub_degree: usize,

    /// Bundling direction. "callees" walks downward (semantic dependencies).
    /// "callers" walks upward (where F is used). "both" walks both.
    #[arg(long, default_value = "callees", value_parser = ["callees", "callers", "both"])]
    bundle: String,

    /// Restrict which feature categories get propagated through bundling.
    /// Comma-separated subset of: bigram, import, string, const, blkcount,
    /// callcount. If unset, all categories propagate (current default).
    /// Useful for "asymmetric bundling": e.g. `--bundle-features
    /// import,string,const` carries the cross-compiler-stable signal through
    /// the neighborhood while keeping bigrams local to each node.
    #[arg(long, value_delimiter = ',')]
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

fn extract_features(
    pe: &PeLoader,
    func: &FunctionAnalysis,
    iat: &HashMap<u64, String>,
    use_bigrams: bool,
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

fn build_graph(
    pe: &PeLoader,
    funcs: &[FunctionAnalysis],
    hasher: &UniversalMinHash,
    use_bigrams: bool,
    hops: usize,
    hub_degree: usize,
    bundle_dir: &str,
    bundle_filter: Option<&FxHashSet<&'static str>>,
) -> Result<Graph<u64>> {
    use rayon::prelude::*;
    let iat = pe.iat()?;
    let func_set: FxHashSet<u64> = funcs.iter().map(|f| f.entry_point).collect();

    // Per-function "own" features.
    let own: FxHashMap<u64, FxHashSet<Feat>> = funcs
        .par_iter()
        .map(|f| (f.entry_point, extract_features(pe, f, &iat, use_bigrams)))
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
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
    iat_a: &HashMap<u64, String>,
    iat_b: &HashMap<u64, String>,
    pe1: &PeLoader,
    pe2: &PeLoader,
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

    // Callee lists side-by-side — directly visualizes inlining differences.
    let calls_a = callee_labels(func_a, pe1, iat_a, names_a);
    let calls_b = callee_labels(func_b, pe2, iat_b, names_b);
    let max = calls_a.len().max(calls_b.len());
    if max > 0 {
        println!("#   callees:");
        for i in 0..max {
            let ca = calls_a.get(i).map(String::as_str).unwrap_or("");
            let cb = calls_b.get(i).map(String::as_str).unwrap_or("");
            let ca = if ca.len() > 50 { &ca[..50] } else { ca };
            let cb = if cb.len() > 50 { &cb[..50] } else { cb };
            println!("#     {:<52} | {}", ca, cb);
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
}

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
            let feats_a = extract_features(pe1, fa, &iat_a, use_bigrams);
            let feats_b = extract_features(pe2, fb, &iat_b, use_bigrams);
            report_pair(
                name, addr_a, addr_b, fa, fb, &feats_a, &feats_b, &alg_match, names_a, names_b,
                &iat_a, &iat_b, pe1, pe2,
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
            let feats_a = extract_features(pe1, func_a, &iat_a, use_bigrams);
            let feats_b = extract_features(pe2, func_b, &iat_b, use_bigrams);

            let alg_b = alg_match.get(addr_a).copied();
            let alg_str = match alg_b {
                None => "<no algorithm match>".to_string(),
                Some(b) if b == *addr_b => "<correct>".to_string(),
                Some(b) => {
                    let alg_names = names_b
                        .get(&b)
                        .and_then(|v| v.first())
                        .cloned()
                        .unwrap_or_default();
                    let trim = if alg_names.len() > 70 {
                        format!("{}…", &alg_names[..70])
                    } else {
                        alg_names
                    };
                    format!("{:#x} ({})", b, trim)
                }
            };

            let name_short = if name.len() > 70 {
                format!("{}…", &name[..70])
            } else {
                name.clone()
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
            println!("#   algorithm matched base → {}", alg_str);

            // Per-category counts and intersection.
            let mut cats: std::collections::BTreeMap<
                &'static str,
                (FxHashSet<Feat>, FxHashSet<Feat>),
            > = Default::default();
            for f in &feats_a {
                cats.entry(feat_category(f)).or_default().0.insert(*f);
            }
            for f in &feats_b {
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
            let inter_all = feats_a.intersection(&feats_b).count();
            let union_all = feats_a.union(&feats_b).count();
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
        }
    };

    let tp_samples = stride_pick(&tp_pool, n);
    let fn_samples = stride_pick(&fn_pool, n);
    dump("TP (algorithm matched correctly)", &tp_samples);
    dump("FN (same name in both, algorithm missed)", &fn_samples);

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

    let config = MatcherConfig {
        k_permutations: args.k,
        lsh_bands: args.bands,
        min_features_for_lsh: args.min_features,
        anchor_threshold: args.anchor,
        propagation_threshold: args.propagate,
        max_propagation_degree: args.max_degree,
        size_mismatch_ratio: 2.0,
        pre_match_on_identifiers: false,
    };
    let hasher = config.hasher(args.seed);

    let use_bigrams = !args.no_bigrams;
    // Resolve the optional bundle-features filter into a static-str set the
    // bundling loop can match against feat_category().
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

    tick(&format!(
        "building base graph (bigrams={}, hops={}, bundle_filter={:?})",
        if use_bigrams { "on" } else { "off" },
        args.hops,
        bundle_filter
    ));
    let g1 = build_graph(
        &pe1,
        &funcs1,
        &hasher,
        use_bigrams,
        args.hops,
        args.hub_degree,
        &args.bundle,
        bundle_filter.as_ref(),
    )?;
    tick("building target graph");
    let g2 = build_graph(
        &pe2,
        &funcs2,
        &hasher,
        use_bigrams,
        args.hops,
        args.hub_degree,
        &args.bundle,
        bundle_filter.as_ref(),
    )?;

    tick("matching");
    let matches = config.run(&g1, &g2);
    tick("done");

    let mut sorted: Vec<(u64, u64)> = matches.into_iter().collect();
    sorted.sort_unstable();

    println!(
        "# matched {} / {} base functions",
        sorted.len(),
        funcs1.len()
    );

    if args.validate {
        tick("loading PDBs");
        let names_a = load_pdb_names(&args.base, &pe1)?;
        let names_b = load_pdb_names(&args.target, &pe2)?;

        // Per-address name sets. Multi-name handling: a function with
        // multiple symbols (COMDAT-folded, public + procedure forms,
        // aliases) gets credit if ANY of its names matches ANY name on the
        // other side.
        let sets_a: HashMap<u64, FxHashSet<&str>> = names_a
            .iter()
            .map(|(&addr, ns)| (addr, ns.iter().map(String::as_str).collect()))
            .collect();
        let sets_b: HashMap<u64, FxHashSet<&str>> = names_b
            .iter()
            .map(|(&addr, ns)| (addr, ns.iter().map(String::as_str).collect()))
            .collect();

        // Universe of names. Used for the baseline: how many distinct names
        // do the two binaries share, and how many base addrs have at least
        // one of their names present in target.
        let names_in_a: FxHashSet<&str> = sets_a.values().flatten().copied().collect();
        let names_in_b: FxHashSet<&str> = sets_b.values().flatten().copied().collect();
        let shared: usize = names_in_a
            .iter()
            .filter(|n| names_in_b.contains(*n))
            .count();
        let baseline_addrs: usize = sets_a
            .iter()
            .filter(|(_, s)| s.iter().any(|n| names_in_b.contains(n)))
            .count();

        tick(&format!(
            "  base PDB: {} addrs / {} unique names. target: {} addrs / {} unique names",
            names_a.len(),
            names_in_a.len(),
            names_b.len(),
            names_in_b.len(),
        ));
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
            baseline_addrs as f64 / sets_a.len().max(1) as f64 * 100.0,
            sets_a.len(),
        );

        // Validate each algorithm match. TP = the matched (a, b) pair shares
        // at least one PDB name. This reuses the same first-public-then-
        // procedure name pool binfold collects for its own database.
        let mut both_named = 0usize;
        let mut tp = 0usize;
        let mut disagree_examples: Vec<(&str, &str)> = Vec::new();
        for (a, b) in &sorted {
            if let (Some(sa), Some(sb)) = (sets_a.get(a), sets_b.get(b)) {
                if sa.is_empty() || sb.is_empty() {
                    continue;
                }
                both_named += 1;
                if sa.iter().any(|n| sb.contains(n)) {
                    tp += 1;
                } else if disagree_examples.len() < 10 {
                    let na = names_a
                        .get(a)
                        .and_then(|v| v.first())
                        .map(String::as_str)
                        .unwrap_or("");
                    let nb = names_b
                        .get(b)
                        .and_then(|v| v.first())
                        .map(String::as_str)
                        .unwrap_or("");
                    disagree_examples.push((na, nb));
                }
            }
        }

        let precision = tp as f64 / both_named.max(1) as f64;
        let recall = tp as f64 / baseline_addrs.max(1) as f64;
        println!("# matches:");
        println!(
            "#   algorithm matched {} / {} base functions",
            sorted.len(),
            funcs1.len()
        );
        println!(
            "#   of matches, {} have PDB names on BOTH sides (validatable)",
            both_named
        );
        println!(
            "#   precision (any-name overlap): {} / {} = {:.2}%",
            tp,
            both_named,
            precision * 100.0
        );
        println!(
            "#   recall vs baseline:           {} / {} = {:.2}%",
            tp,
            baseline_addrs,
            recall * 100.0
        );
        if !disagree_examples.is_empty() {
            println!("# example disagreements (first name shown each side):");
            for (na, nb) in &disagree_examples {
                let na = if na.len() > 80 { &na[..80] } else { na };
                let nb = if nb.len() > 80 { &nb[..80] } else { nb };
                println!("#   {}\n# ≠ {}", na, nb);
            }
        }

        if args.inspect_samples > 0 {
            inspect_samples(
                args.inspect_samples,
                &sorted,
                &names_a,
                &names_b,
                &names_in_a,
                &names_in_b,
                &funcs1,
                &funcs2,
                &pe1,
                &pe2,
                !args.no_bigrams,
            )?;
        }

        if !args.inspect_patterns.is_empty() {
            inspect_patterns(
                &args.inspect_patterns,
                args.inspect_pattern_limit,
                &sorted,
                &names_a,
                &names_b,
                &funcs1,
                &funcs2,
                &pe1,
                &pe2,
                !args.no_bigrams,
            )?;
        }
    }

    println!("# {:>16} -> {:>16}", "base", "target");
    for (a, b) in sorted.iter().take(args.limit) {
        println!("{:#018x} -> {:#018x}", a, b);
    }
    if sorted.len() > args.limit {
        println!("... ({} more)", sorted.len() - args.limit);
    }

    Ok(())
}
