//! Render side-by-side k-hop neighborhood diff graphs from a fuzzy_match cache.
//!
//! Use after running `fuzzy_match --emit-matches <path>` once. Iterate on the
//! visualization without re-running the matcher.

use anyhow::{Context, Result, anyhow};
use binfold::mmap_source::MmapSource;
use binfold::pe_loader::{FunctionAnalysis, PeLoader};
use clap::Parser;
use pdb::{FallibleIterator, PDB, SymbolData};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(about = "Render side-by-side neighborhood diff graphs from a fuzzy_match result")]
struct Args {
    base: PathBuf,
    target: PathBuf,

    /// Cache file produced by `fuzzy_match --emit-matches`. Required.
    #[arg(long)]
    matches_cache: PathBuf,

    /// Output directory for .dot, .svg, .match-map.txt, index.md.
    #[arg(long, default_value = "graph-diff-out")]
    out: PathBuf,

    /// Substring patterns over PDB names. Each name found in BOTH binaries
    /// gets a graph rendered. Repeatable. Neighborhood mode (one graph per
    /// pattern hit, k-hop around the focal node).
    #[arg(long = "pattern")]
    patterns: Vec<String>,

    /// Specific BASE addresses to render (bypasses --pattern). Hex notation.
    #[arg(long = "addr", value_parser = parse_hex)]
    addrs: Vec<u64>,

    /// Anchor mode: substring patterns whose name-matches across BOTH
    /// binaries form an "anchor set". The tool computes the path-union
    /// subgraph connecting anchors on each side (BFS shortest paths up to
    /// --max-path-hops between every pair of anchors) and renders a single
    /// combined diff per binary pair. Use to see the *connectivity skeleton*
    /// between known landmarks. Mutually exclusive with --pattern/--addr.
    #[arg(long = "anchor")]
    anchors: Vec<String>,

    /// In anchor mode, max path length to consider when connecting anchors.
    /// Anchors farther apart than this are reported as unreachable and
    /// rendered as isolated nodes. Higher = more intermediate nodes appear.
    #[arg(long, default_value_t = 4)]
    max_path_hops: usize,

    /// Cap matches inspected per pattern.
    #[arg(long, default_value_t = 5)]
    pattern_limit: usize,

    /// Neighborhood depth. Default 1 keeps graphs scannable; bump to 2 for
    /// deeper context but expect 5-10× more nodes.
    #[arg(long, default_value_t = 1)]
    hops: usize,

    /// Direction to walk: callees, callers, or both. Default callees: a
    /// focal function's outgoing call list is the part most diagnostic of
    /// "what does it do". Use `both` only with hops=1, otherwise the graph
    /// explodes.
    #[arg(long, default_value = "callees", value_parser = ["callees", "callers", "both"])]
    direction: String,

    /// Hub gate: don't expand BFS through any node with more than N edges
    /// in the chosen direction. Lower = tighter graph. Aggressive default
    /// (8) suppresses the worst offenders (memcpy, log helpers, allocators).
    #[arg(long, default_value_t = 8)]
    hub_degree: usize,

    /// Cap on visible nodes per side. Excess nodes (BFS frontier) are
    /// dropped and a small "+N more" placeholder is added. Prevents
    /// pathological focal points from producing unreadable graphs.
    #[arg(long, default_value_t = 60)]
    max_nodes: usize,

    /// After writing .dot, invoke `dot -Tsvg` to produce an .svg next to it.
    /// Requires Graphviz `dot` on PATH.
    #[arg(long)]
    svg: bool,

    /// Skip writing per-pair .match-map.txt sidecars.
    #[arg(long)]
    no_match_map: bool,

    /// Discovery mode: dump a TSV of every PDB name present in BOTH binaries
    /// to stdout, with match status and call-graph degree info, then exit.
    /// Suppresses all rendering. Use this to find which subsystems are worth
    /// investigating: pipe through awk/sort/grep to identify clusters.
    /// Columns: status, name, base_addr, target_addr, base_callees, base_callers.
    #[arg(long)]
    dump_shared: bool,

    /// Symbol-set file (sections of exact mangled names — see
    /// ue-modding-symbols.set). Triggers per-section anchor-mode rendering.
    #[arg(long)]
    symbol_set: Option<PathBuf>,

    /// In symbol-set mode, dump per-anchor-pair path-structure TSV to stdout
    /// instead of rendering graphs. Columns: section, pair_a, pair_b,
    /// len_base, len_target, gap, b_correct, b_wrong, b_missed, b_import,
    /// t_correct, t_wrong, t_missed, t_import, match_overlap. Use to
    /// quantify cross-binary path asymmetry for tuning.
    #[arg(long)]
    analyze_paths: bool,
}

fn parse_hex(s: &str) -> Result<u64, String> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(trimmed, 16).map_err(|e| format!("bad hex '{}': {}", s, e))
}

// ---------------------------------------------------------------------------
// Matches cache I/O — must match fuzzy_match::write_matches_cache layout.
// ---------------------------------------------------------------------------

struct MatchesCache {
    matches: FxHashMap<u64, u64>,
    synth_a: FxHashMap<u64, u64>,
    synth_b: FxHashMap<u64, u64>,
    #[allow(dead_code)]
    data_synth_a: FxHashMap<u64, u64>,
    #[allow(dead_code)]
    data_synth_b: FxHashMap<u64, u64>,
}

fn parse_matches_cache(path: &Path) -> Result<MatchesCache> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading matches cache {}", path.display()))?;
    let mut matches = FxHashMap::default();
    let mut synth_a = FxHashMap::default();
    let mut synth_b = FxHashMap::default();
    let mut data_synth_a = FxHashMap::default();
    let mut data_synth_b = FxHashMap::default();

    enum Sec {
        None,
        Meta,
        Matches,
        SynthA,
        SynthB,
        DataA,
        DataB,
    }
    let mut sec = Sec::None;

    for (lineno, raw) in content.lines().enumerate() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            sec = match name {
                "meta" => Sec::Meta,
                "matches" => Sec::Matches,
                "synth_a" => Sec::SynthA,
                "synth_b" => Sec::SynthB,
                "data_synth_a" => Sec::DataA,
                "data_synth_b" => Sec::DataB,
                _ => Sec::None,
            };
            continue;
        }
        let mut parts = line.splitn(2, '\t');
        let (Some(k), Some(v)) = (parts.next(), parts.next()) else {
            continue;
        };
        let parse_u64 = |s: &str| -> Result<u64> {
            if s.starts_with("0x") || s.starts_with("0X") {
                parse_hex(s).map_err(|e| anyhow!("line {}: {}", lineno + 1, e))
            } else {
                s.parse::<u64>()
                    .with_context(|| format!("line {}: bad u64 '{}'", lineno + 1, s))
            }
        };
        match sec {
            Sec::Meta => {} // ignored at parse time
            Sec::Matches => {
                matches.insert(parse_u64(k)?, parse_u64(v)?);
            }
            Sec::SynthA => {
                synth_a.insert(parse_u64(k)?, parse_u64(v)?);
            }
            Sec::SynthB => {
                synth_b.insert(parse_u64(k)?, parse_u64(v)?);
            }
            Sec::DataA => {
                data_synth_a.insert(parse_u64(k)?, parse_u64(v)?);
            }
            Sec::DataB => {
                data_synth_b.insert(parse_u64(k)?, parse_u64(v)?);
            }
            Sec::None => {}
        }
    }

    Ok(MatchesCache {
        matches,
        synth_a,
        synth_b,
        data_synth_a,
        data_synth_b,
    })
}

// ---------------------------------------------------------------------------
// PE / PDB loading — duplicated from fuzzy_match for now, small and stable.
// ---------------------------------------------------------------------------

fn analyze(path: &Path) -> Result<(PeLoader, Vec<FunctionAnalysis>)> {
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

fn load_pdb_names(exe_path: &Path, pe: &PeLoader) -> Result<HashMap<u64, Vec<String>>> {
    let pdb_path = exe_path.with_extension("pdb");
    let source = MmapSource::new(&pdb_path)?;
    let mut pdb = PDB::open(source)?;
    let address_map = pdb.address_map()?;
    let image_base = pe.image_base();
    let mut names: HashMap<u64, Vec<String>> = HashMap::new();

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

    for v in names.values_mut() {
        v.sort();
        v.dedup();
    }
    Ok(names)
}

// ---------------------------------------------------------------------------
// Subgraph extraction.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeStatus {
    Correct,
    Wrong,
    Missed,
    Import,
}

fn color_of(s: NodeStatus) -> &'static str {
    match s {
        NodeStatus::Correct => "palegreen",
        NodeStatus::Wrong => "lightcoral",
        NodeStatus::Missed => "lightgoldenrod1",
        NodeStatus::Import => "lightgray",
    }
}

fn names_overlap(a: Option<&Vec<String>>, b: Option<&Vec<String>>) -> Option<bool> {
    match (a, b) {
        (Some(a), Some(b)) if !a.is_empty() && !b.is_empty() => {
            let bset: FxHashSet<&str> = b.iter().map(String::as_str).collect();
            Some(a.iter().any(|n| bset.contains(n.as_str())))
        }
        _ => None,
    }
}

fn classify_base(
    addr: u64,
    funcs_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    iat: &HashMap<u64, String>,
    alg_match: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
) -> NodeStatus {
    if iat.contains_key(&addr) || !funcs_by_ep.contains_key(&addr) {
        return NodeStatus::Import;
    }
    match alg_match.get(&addr) {
        Some(&target) => match names_overlap(names_a.get(&addr), names_b.get(&target)) {
            Some(true) => NodeStatus::Correct,
            Some(false) => NodeStatus::Wrong,
            // Pair found but at least one side has no name — treat as "wrong"
            // to flag it visually; the match-map sidecar shows the detail.
            None => NodeStatus::Wrong,
        },
        None => NodeStatus::Missed,
    }
}

fn classify_target(
    addr: u64,
    funcs_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    iat: &HashMap<u64, String>,
    alg_match_rev: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
) -> NodeStatus {
    if iat.contains_key(&addr) || !funcs_by_ep.contains_key(&addr) {
        return NodeStatus::Import;
    }
    match alg_match_rev.get(&addr) {
        Some(&base) => match names_overlap(names_a.get(&base), names_b.get(&addr)) {
            Some(true) => NodeStatus::Correct,
            Some(false) => NodeStatus::Wrong,
            None => NodeStatus::Wrong,
        },
        None => NodeStatus::Missed,
    }
}

/// Strict BFS from `start` up to `hops`, walking call edges in the chosen
/// direction(s). Hub gate: skip expanding through any node with more than
/// `hub_degree` neighbors. Cap: stop adding new visited nodes once
/// `max_nodes` is reached (returns `truncated=true`).
///
/// Edges returned are the call edges among the visited set, regardless of
/// the BFS direction — so the rendered graph shows full connectivity within
/// the visible neighborhood, not just the BFS spanning tree.
fn bfs_neighborhood(
    start: u64,
    funcs_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    callers_map: &FxHashMap<u64, Vec<u64>>,
    hops: usize,
    direction: &str,
    hub_degree: usize,
    max_nodes: usize,
) -> (FxHashSet<u64>, Vec<(u64, u64)>, bool) {
    let mut visited: FxHashSet<u64> = FxHashSet::default();
    let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
    visited.insert(start);
    queue.push_back((start, 0));
    let walk_callees = direction == "callees" || direction == "both";
    let walk_callers = direction == "callers" || direction == "both";
    let mut truncated = false;

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= hops {
            continue;
        }
        // Collect this node's neighbors in active direction(s).
        let mut neighbors: Vec<u64> = Vec::new();
        if walk_callees && let Some(f) = funcs_by_ep.get(&node) {
            for c in &f.calls {
                neighbors.push(c.target);
            }
        }
        if walk_callers && let Some(callers) = callers_map.get(&node) {
            for &c in callers {
                neighbors.push(c);
            }
        }
        // Hub gate: don't expand through a node with too many edges (except
        // the focal node itself — we always want its full immediate set).
        if node != start && neighbors.len() > hub_degree {
            continue;
        }
        for n in neighbors {
            if visited.contains(&n) {
                continue;
            }
            if visited.len() >= max_nodes {
                truncated = true;
                continue;
            }
            visited.insert(n);
            queue.push_back((n, depth + 1));
        }
    }

    // Edge collection: every call edge whose both endpoints are visible.
    // Do this as a separate pass so we get full connectivity within the
    // neighborhood, not just the BFS tree.
    let mut edges: Vec<(u64, u64)> = Vec::new();
    for &n in &visited {
        if let Some(f) = funcs_by_ep.get(&n) {
            for c in &f.calls {
                if visited.contains(&c.target) && c.target != n {
                    edges.push((n, c.target));
                }
            }
        }
    }
    edges.sort_unstable();
    edges.dedup();
    (visited, edges, truncated)
}

/// Parse a symbol-set file: `[section]` headers, bare lines = exact patterns,
/// `#` lines are comments. Returns sections in file order.
fn parse_symbol_set(path: &Path) -> Result<Vec<(String, Vec<String>)>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading symbol set {}", path.display()))?;
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(s) = current.take() {
                sections.push(s);
            }
            current = Some((name.to_string(), Vec::new()));
        } else if let Some((_, patterns)) = current.as_mut() {
            patterns.push(line.to_string());
        }
    }
    if let Some(s) = current.take() {
        sections.push(s);
    }
    Ok(sections)
}

/// BFS shortest path from `start` to `end`. Returns the full node sequence
/// (start..end inclusive), or None if not reachable within `max_hops`.
fn shortest_path(
    start: u64,
    end: u64,
    funcs_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    callers_map: &FxHashMap<u64, Vec<u64>>,
    direction: &str,
    max_hops: usize,
) -> Option<Vec<u64>> {
    if start == end {
        return Some(vec![start]);
    }
    let mut parent: FxHashMap<u64, u64> = FxHashMap::default();
    let mut depth: FxHashMap<u64, usize> = FxHashMap::default();
    let mut queue: VecDeque<u64> = VecDeque::new();
    depth.insert(start, 0);
    queue.push_back(start);
    let walk_callees = direction == "callees" || direction == "both";
    let walk_callers = direction == "callers" || direction == "both";

    while let Some(node) = queue.pop_front() {
        let d = depth[&node];
        if d >= max_hops {
            continue;
        }
        let mut neighbors: Vec<u64> = Vec::new();
        if walk_callees && let Some(f) = funcs_by_ep.get(&node) {
            for c in &f.calls {
                neighbors.push(c.target);
            }
        }
        if walk_callers && let Some(callers) = callers_map.get(&node) {
            for &c in callers {
                neighbors.push(c);
            }
        }
        for n in neighbors {
            if depth.contains_key(&n) {
                continue;
            }
            depth.insert(n, d + 1);
            parent.insert(n, node);
            if n == end {
                let mut path = vec![end];
                let mut cur = end;
                while let Some(&p) = parent.get(&cur) {
                    path.push(p);
                    cur = p;
                    if cur == start {
                        break;
                    }
                }
                path.reverse();
                return Some(path);
            }
            queue.push_back(n);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn analyze_paths(
    sections: &[(String, Vec<String>)],
    by_name_a: &FxHashMap<&str, Vec<u64>>,
    by_name_b: &FxHashMap<&str, Vec<u64>>,
    funcs1_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    funcs2_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    callers_a: &FxHashMap<u64, Vec<u64>>,
    callers_b: &FxHashMap<u64, Vec<u64>>,
    matches: &FxHashMap<u64, u64>,
    matches_rev: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
    iat_a: &HashMap<u64, String>,
    iat_b: &HashMap<u64, String>,
    direction: &str,
    max_hops: usize,
) -> Result<()> {
    println!(
        "section\tpair_a\tpair_b\tlen_base\tlen_target\tgap\tb_correct\tb_wrong\tb_missed\tb_import\tt_correct\tt_wrong\tt_missed\tt_import\tmatch_overlap"
    );

    for (section, patterns) in sections {
        // Resolve patterns (exact name → first address).
        let mut anchors: Vec<(String, u64, u64)> = Vec::new();
        for pat in patterns {
            let (Some(addrs_a), Some(addrs_b)) =
                (by_name_a.get(pat.as_str()), by_name_b.get(pat.as_str()))
            else {
                continue;
            };
            if addrs_a.is_empty() || addrs_b.is_empty() {
                continue;
            }
            let addr_a = addrs_a[0];
            let addr_b = addrs_b[0];
            if !funcs1_by_ep.contains_key(&addr_a) || !funcs2_by_ep.contains_key(&addr_b) {
                continue;
            }
            anchors.push((pat.clone(), addr_a, addr_b));
        }
        if anchors.len() < 2 {
            eprintln!(
                "section '{}': only {} resolvable anchors, skipping",
                section,
                anchors.len()
            );
            continue;
        }

        // Dedup by address (mangled+demangled aliases collapse).
        let mut seen_a: FxHashSet<u64> = FxHashSet::default();
        let mut deduped: Vec<(String, u64, u64)> = Vec::new();
        for a in anchors {
            if seen_a.insert(a.1) {
                deduped.push(a);
            }
        }
        let anchors = deduped;
        eprintln!("section '{}': {} unique anchors", section, anchors.len());

        // All ordered pairs (i, j) with i != j.
        for i in 0..anchors.len() {
            for j in 0..anchors.len() {
                if i == j {
                    continue;
                }
                let (name_i, a_i, b_i) = (anchors[i].0.as_str(), anchors[i].1, anchors[i].2);
                let (name_j, _a_j, _b_j) = (anchors[j].0.as_str(), anchors[j].1, anchors[j].2);
                let a_j = anchors[j].1;
                let b_j = anchors[j].2;

                let path_b = shortest_path(a_i, a_j, funcs1_by_ep, callers_a, direction, max_hops);
                let path_t = shortest_path(b_i, b_j, funcs2_by_ep, callers_b, direction, max_hops);

                // Lengths exclude endpoints (intermediate count). 0 = direct
                // edge; -1 = unreachable.
                let len_base: i32 = path_b.as_ref().map(|p| (p.len() as i32) - 2).unwrap_or(-1);
                let len_target: i32 = path_t.as_ref().map(|p| (p.len() as i32) - 2).unwrap_or(-1);

                let intermediates_b: Vec<u64> = path_b
                    .as_ref()
                    .map(|p| {
                        if p.len() >= 2 {
                            p[1..p.len() - 1].to_vec()
                        } else {
                            Vec::new()
                        }
                    })
                    .unwrap_or_default();
                let intermediates_t: Vec<u64> = path_t
                    .as_ref()
                    .map(|p| {
                        if p.len() >= 2 {
                            p[1..p.len() - 1].to_vec()
                        } else {
                            Vec::new()
                        }
                    })
                    .unwrap_or_default();

                let (bc, bw, bm, bi) = classify_path(
                    &intermediates_b,
                    funcs1_by_ep,
                    iat_a,
                    matches,
                    names_a,
                    names_b,
                );
                let (tc, tw, tm, ti) = classify_path_target(
                    &intermediates_t,
                    funcs2_by_ep,
                    iat_b,
                    matches_rev,
                    names_a,
                    names_b,
                );

                // "Match overlap": of base intermediates that have an alg
                // match, how many of those matched-target-addrs appear in
                // the target path? 0..1 ratio (formatted as 0/0 if no
                // matched intermediates exist).
                let mut overlap_num = 0usize;
                let mut overlap_den = 0usize;
                let target_set: FxHashSet<u64> = intermediates_t.iter().copied().collect();
                for &n in &intermediates_b {
                    if let Some(&t) = matches.get(&n) {
                        overlap_den += 1;
                        if target_set.contains(&t) {
                            overlap_num += 1;
                        }
                    }
                }

                let gap = if len_base >= 0 && len_target >= 0 {
                    format!("{}", len_target - len_base)
                } else {
                    "?".into()
                };

                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}/{}",
                    section,
                    name_i,
                    name_j,
                    len_base,
                    len_target,
                    gap,
                    bc,
                    bw,
                    bm,
                    bi,
                    tc,
                    tw,
                    tm,
                    ti,
                    overlap_num,
                    overlap_den,
                );
            }
        }
    }
    Ok(())
}

fn classify_path(
    intermediates: &[u64],
    funcs_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    iat: &HashMap<u64, String>,
    matches: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
) -> (usize, usize, usize, usize) {
    let mut c = 0;
    let mut w = 0;
    let mut m = 0;
    let mut imp = 0;
    for &n in intermediates {
        match classify_base(n, funcs_by_ep, iat, matches, names_a, names_b) {
            NodeStatus::Correct => c += 1,
            NodeStatus::Wrong => w += 1,
            NodeStatus::Missed => m += 1,
            NodeStatus::Import => imp += 1,
        }
    }
    (c, w, m, imp)
}

fn classify_path_target(
    intermediates: &[u64],
    funcs_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    iat: &HashMap<u64, String>,
    matches_rev: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
) -> (usize, usize, usize, usize) {
    let mut c = 0;
    let mut w = 0;
    let mut m = 0;
    let mut imp = 0;
    for &n in intermediates {
        match classify_target(n, funcs_by_ep, iat, matches_rev, names_a, names_b) {
            NodeStatus::Correct => c += 1,
            NodeStatus::Wrong => w += 1,
            NodeStatus::Missed => m += 1,
            NodeStatus::Import => imp += 1,
        }
    }
    (c, w, m, imp)
}

/// Compute the path-union subgraph connecting a set of anchor nodes.
/// For each ordered anchor pair (A, B), runs BFS from A; if B is reachable
/// within `max_hops`, every node on the shortest path is added to the
/// visible set. Returns:
///   - visible nodes (anchors + on-path intermediates)
///   - call edges among the visible set (always rendered as caller→callee)
///   - reachability stats: list of (from_anchor, to_anchor, distance)
///
/// For `direction == "both"`, BFS treats the call graph as undirected (path
/// can flow forward or backward through call edges). For `"callees"` it
/// follows caller→callee only; `"callers"` follows the reverse.
fn compute_anchor_subgraph(
    anchors: &[u64],
    funcs_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    callers_map: &FxHashMap<u64, Vec<u64>>,
    direction: &str,
    max_hops: usize,
) -> (FxHashSet<u64>, Vec<(u64, u64)>, Vec<(u64, u64, usize)>) {
    let mut visible: FxHashSet<u64> = anchors.iter().copied().collect();
    let mut reach: Vec<(u64, u64, usize)> = Vec::new();
    let walk_callees = direction == "callees" || direction == "both";
    let walk_callers = direction == "callers" || direction == "both";

    for &start in anchors {
        // BFS computing parent pointers + depth.
        let mut parent: FxHashMap<u64, u64> = FxHashMap::default();
        let mut depth: FxHashMap<u64, usize> = FxHashMap::default();
        let mut queue: VecDeque<u64> = VecDeque::new();
        depth.insert(start, 0);
        queue.push_back(start);
        while let Some(node) = queue.pop_front() {
            let d = depth[&node];
            if d >= max_hops {
                continue;
            }
            let mut neighbors: Vec<u64> = Vec::new();
            if walk_callees && let Some(f) = funcs_by_ep.get(&node) {
                for c in &f.calls {
                    neighbors.push(c.target);
                }
            }
            if walk_callers && let Some(callers) = callers_map.get(&node) {
                for &c in callers {
                    neighbors.push(c);
                }
            }
            for n in neighbors {
                if depth.contains_key(&n) {
                    continue;
                }
                depth.insert(n, d + 1);
                parent.insert(n, node);
                queue.push_back(n);
            }
        }
        // For each other anchor reached, walk parents back to start, adding
        // every node along the way to the visible set.
        for &target in anchors {
            if target == start {
                continue;
            }
            let Some(&dist) = depth.get(&target) else {
                continue;
            };
            reach.push((start, target, dist));
            let mut cur = target;
            while cur != start {
                visible.insert(cur);
                let Some(&p) = parent.get(&cur) else {
                    break;
                };
                cur = p;
            }
        }
    }

    // Collect all call edges among the visible set.
    let mut edges: Vec<(u64, u64)> = Vec::new();
    for &n in &visible {
        if let Some(f) = funcs_by_ep.get(&n) {
            for c in &f.calls {
                if visible.contains(&c.target) && c.target != n {
                    edges.push((n, c.target));
                }
            }
        }
    }
    edges.sort_unstable();
    edges.dedup();
    (visible, edges, reach)
}

fn build_callers(funcs: &[FunctionAnalysis]) -> FxHashMap<u64, Vec<u64>> {
    let mut callers: FxHashMap<u64, Vec<u64>> = FxHashMap::default();
    for f in funcs {
        for call in &f.calls {
            if call.target != f.entry_point {
                callers.entry(call.target).or_default().push(f.entry_point);
            }
        }
    }
    callers
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn short_name(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    } else {
        s.to_string()
    }
}

fn node_label(
    addr: u64,
    names: &HashMap<u64, Vec<String>>,
    iat: &HashMap<u64, String>,
    synth: Option<u64>,
) -> String {
    let core = if let Some(import) = iat.get(&addr) {
        format!("import:{}", import)
    } else if let Some(n) = names.get(&addr).and_then(|v| v.first()) {
        n.clone()
    } else {
        format!("?{:#x}", addr)
    };
    let trimmed = short_name(&core, 50);
    let synth_str = synth.map(|s| format!("\\nS={}", s)).unwrap_or_default();
    format!("{}\\n{:#x}{}", dot_escape(&trimmed), addr, synth_str)
}

fn write_legend(dot: &mut String) {
    writeln!(dot, "  subgraph cluster_legend {{").unwrap();
    writeln!(dot, "    label=\"legend (thick blue border = anchor / focal)\"; style=rounded; color=\"#cccccc\";").unwrap();
    for (lbl, st) in [
        ("correct", NodeStatus::Correct),
        ("wrong", NodeStatus::Wrong),
        ("missed", NodeStatus::Missed),
        ("import", NodeStatus::Import),
    ] {
        writeln!(
            dot,
            "    \"leg_{}\" [label=\"{}\", fillcolor=\"{}\", shape=box, style=\"filled,rounded\"];",
            lbl,
            lbl,
            color_of(st)
        )
        .unwrap();
    }
    writeln!(dot, "  }}").unwrap();
}

fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    cleaned.chars().take(80).collect()
}

#[allow(clippy::too_many_arguments)]
fn render_cluster(
    dot: &mut String,
    side_tag: char, // 'a' or 'b' — used as node-id prefix
    cluster_label: &str,
    nodes: &FxHashSet<u64>,
    edges: &[(u64, u64)],
    statuses: &FxHashMap<u64, NodeStatus>,
    names: &HashMap<u64, Vec<String>>,
    iat: &HashMap<u64, String>,
    synth: &FxHashMap<u64, u64>,
    anchors: &FxHashSet<u64>,
    truncated: bool,
) {
    writeln!(dot, "  subgraph cluster_{} {{", side_tag).unwrap();
    writeln!(dot, "    label=\"{}\";", cluster_label).unwrap();
    writeln!(dot, "    style=rounded;").unwrap();
    writeln!(dot, "    color=\"#888888\";").unwrap();
    let mut sorted: Vec<u64> = nodes.iter().copied().collect();
    sorted.sort_unstable();
    for &n in &sorted {
        let s = statuses.get(&n).copied().unwrap_or(NodeStatus::Missed);
        let label = node_label(n, names, iat, synth.get(&n).copied());
        // Anchors get a thick blue border ON TOP of the regular fill color,
        // so you can see at a glance "this is a known landmark" AND "is the
        // algorithm correct about it".
        let extra = if anchors.contains(&n) {
            ", penwidth=2.5, color=\"#1f4e79\""
        } else {
            ""
        };
        writeln!(
            dot,
            "    \"{}_{:x}\" [label=\"{}\", fillcolor=\"{}\"{}];",
            side_tag,
            n,
            label,
            color_of(s),
            extra
        )
        .unwrap();
    }
    for &(a, b) in edges {
        writeln!(
            dot,
            "    \"{}_{:x}\" -> \"{}_{:x}\";",
            side_tag, a, side_tag, b
        )
        .unwrap();
    }
    if truncated {
        writeln!(
            dot,
            "    \"{}_truncated\" [label=\"… more nodes truncated\\n(raise --max-nodes)\", fillcolor=\"#dddddd\", shape=note, style=filled];",
            side_tag
        )
        .unwrap();
    }
    writeln!(dot, "  }}").unwrap();
}

struct ReportRow {
    name: String,
    base_count: usize,
    target_count: usize,
    correct: usize,
    wrong: usize,
    missed: usize,
    file_stem: String,
}

#[allow(clippy::too_many_arguments)]
fn render_pair(
    name: &str,
    addr_a: u64,
    addr_b: u64,
    funcs1_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    funcs2_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    callers_a: &FxHashMap<u64, Vec<u64>>,
    callers_b: &FxHashMap<u64, Vec<u64>>,
    alg_match: &FxHashMap<u64, u64>,
    alg_match_rev: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
    iat_a: &HashMap<u64, String>,
    iat_b: &HashMap<u64, String>,
    cache: &MatchesCache,
    args: &Args,
) -> Result<ReportRow> {
    let (nodes_a, edges_a, trunc_a) = bfs_neighborhood(
        addr_a,
        funcs1_by_ep,
        callers_a,
        args.hops,
        &args.direction,
        args.hub_degree,
        args.max_nodes,
    );
    let (nodes_b, edges_b, trunc_b) = bfs_neighborhood(
        addr_b,
        funcs2_by_ep,
        callers_b,
        args.hops,
        &args.direction,
        args.hub_degree,
        args.max_nodes,
    );
    eprintln!(
        "    base: {} nodes{}  target: {} nodes{}",
        nodes_a.len(),
        if trunc_a { " (TRUNCATED)" } else { "" },
        nodes_b.len(),
        if trunc_b { " (TRUNCATED)" } else { "" },
    );

    // Classify every node once (also drives the report stats).
    let mut statuses_a: FxHashMap<u64, NodeStatus> = FxHashMap::default();
    let mut statuses_b: FxHashMap<u64, NodeStatus> = FxHashMap::default();
    let mut correct = 0usize;
    let mut wrong = 0usize;
    let mut missed = 0usize;
    for &n in &nodes_a {
        let s = classify_base(n, funcs1_by_ep, iat_a, alg_match, names_a, names_b);
        if n != addr_a {
            match s {
                NodeStatus::Correct => correct += 1,
                NodeStatus::Wrong => wrong += 1,
                NodeStatus::Missed => missed += 1,
                _ => {}
            }
        }
        statuses_a.insert(n, s);
    }
    for &n in &nodes_b {
        let s = classify_target(n, funcs2_by_ep, iat_b, alg_match_rev, names_a, names_b);
        statuses_b.insert(n, s);
    }
    let anchors_a: FxHashSet<u64> = std::iter::once(addr_a).collect();
    let anchors_b: FxHashSet<u64> = std::iter::once(addr_b).collect();

    // Assemble dot.
    let mut dot = String::new();
    writeln!(dot, "digraph G {{").unwrap();
    writeln!(dot, "  rankdir=TB;").unwrap();
    writeln!(dot, "  compound=true;").unwrap();
    writeln!(
        dot,
        "  node [shape=box, style=\"filled,rounded\", fontname=Helvetica, fontsize=10];"
    )
    .unwrap();
    writeln!(dot, "  edge [color=\"#666666\", arrowsize=0.7];").unwrap();
    writeln!(dot, "  labelloc=\"t\"; fontsize=12;").unwrap();
    writeln!(
        dot,
        "  label=\"{}\\nhops={} direction={}  base={:#x}  target={:#x}\";",
        dot_escape(name),
        args.hops,
        args.direction,
        addr_a,
        addr_b
    )
    .unwrap();

    render_cluster(
        &mut dot,
        'a',
        &format!(
            "BASE  ({} nodes{})",
            nodes_a.len(),
            if trunc_a { ", truncated" } else { "" }
        ),
        &nodes_a,
        &edges_a,
        &statuses_a,
        names_a,
        iat_a,
        &cache.synth_a,
        &anchors_a,
        trunc_a,
    );
    render_cluster(
        &mut dot,
        'b',
        &format!(
            "TARGET  ({} nodes{})",
            nodes_b.len(),
            if trunc_b { ", truncated" } else { "" }
        ),
        &nodes_b,
        &edges_b,
        &statuses_b,
        names_b,
        iat_b,
        &cache.synth_b,
        &anchors_b,
        trunc_b,
    );

    write_legend(&mut dot);

    writeln!(dot, "}}").unwrap();

    let stem = sanitize(name);
    let dot_path = args.out.join(format!("{}.dot", stem));
    fs::write(&dot_path, &dot)?;

    if args.svg {
        let svg_path = args.out.join(format!("{}.svg", stem));
        let res = std::process::Command::new("dot")
            .arg("-Tsvg")
            .arg(&dot_path)
            .arg("-o")
            .arg(&svg_path)
            .status();
        match res {
            Ok(s) if s.success() => {}
            Ok(s) => eprintln!("  dot exited {}: {}", s, dot_path.display()),
            Err(e) => eprintln!("  dot invocation failed: {} (skipping {}.svg)", e, stem),
        }
    }

    if !args.no_match_map {
        write_match_map(
            &args.out.join(format!("{}.match-map.txt", stem)),
            name,
            addr_a,
            addr_b,
            &nodes_a,
            &nodes_b,
            &statuses_a,
            &statuses_b,
            alg_match,
            alg_match_rev,
            names_a,
            names_b,
        )?;
    }

    Ok(ReportRow {
        name: name.to_string(),
        base_count: nodes_a.len(),
        target_count: nodes_b.len(),
        correct,
        wrong,
        missed,
        file_stem: stem,
    })
}

#[allow(clippy::too_many_arguments)]
fn write_match_map(
    path: &Path,
    name: &str,
    addr_a: u64,
    addr_b: u64,
    nodes_a: &FxHashSet<u64>,
    nodes_b: &FxHashSet<u64>,
    statuses_a: &FxHashMap<u64, NodeStatus>,
    statuses_b: &FxHashMap<u64, NodeStatus>,
    alg_match: &FxHashMap<u64, u64>,
    alg_match_rev: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
) -> Result<()> {
    let mut s = String::new();
    writeln!(s, "focal: {}", name).unwrap();
    writeln!(s, "  base   {:#x}", addr_a).unwrap();
    writeln!(s, "  target {:#x}", addr_b).unwrap();
    writeln!(s).unwrap();
    writeln!(s, "BASE neighborhood ({} nodes):", nodes_a.len()).unwrap();
    let mut sorted_a: Vec<u64> = nodes_a.iter().copied().collect();
    sorted_a.sort_unstable();
    for n in sorted_a {
        let st = statuses_a.get(&n).copied().unwrap_or(NodeStatus::Missed);
        let line = format_base_node_line(n, n == addr_a, st, alg_match, names_a, names_b);
        writeln!(s, "{}", line).unwrap();
    }
    writeln!(s).unwrap();
    writeln!(s, "TARGET neighborhood ({} nodes):", nodes_b.len()).unwrap();
    let mut sorted_b: Vec<u64> = nodes_b.iter().copied().collect();
    sorted_b.sort_unstable();
    for n in sorted_b {
        let st = statuses_b.get(&n).copied().unwrap_or(NodeStatus::Missed);
        let line = format_target_node_line(n, n == addr_b, st, alg_match_rev, names_a, names_b);
        writeln!(s, "{}", line).unwrap();
    }
    fs::write(path, s)?;
    Ok(())
}

fn format_base_node_line(
    n: u64,
    is_anchor: bool,
    st: NodeStatus,
    alg_match: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
) -> String {
    let nm = names_a
        .get(&n)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();
    let nm = short_name(&nm, 60);
    let prefix = if is_anchor { "* " } else { "  " };
    match st {
        NodeStatus::Correct => {
            let t = alg_match.get(&n).copied().unwrap_or(0);
            format!("{}{:#x}  ↔ {:#x}  [correct]  {}", prefix, n, t, nm)
        }
        NodeStatus::Wrong => {
            let t = alg_match.get(&n).copied().unwrap_or(0);
            let claim = names_b
                .get(&t)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let claim = short_name(&claim, 60);
            format!(
                "{}{:#x}  → {:#x}  [WRONG]  base={}  target_claim={}",
                prefix, n, t, nm, claim
            )
        }
        NodeStatus::Missed => format!("{}{:#x}  <unmatched>  {}", prefix, n, nm),
        NodeStatus::Import => format!("{}{:#x}  [import/external]", prefix, n),
    }
}

fn format_target_node_line(
    n: u64,
    is_anchor: bool,
    st: NodeStatus,
    alg_match_rev: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
) -> String {
    let nm = names_b
        .get(&n)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();
    let nm = short_name(&nm, 60);
    let prefix = if is_anchor { "* " } else { "  " };
    match st {
        NodeStatus::Correct => {
            let b = alg_match_rev.get(&n).copied().unwrap_or(0);
            format!("{}{:#x}  ↔ {:#x}  [correct]  {}", prefix, n, b, nm)
        }
        NodeStatus::Wrong => {
            let b = alg_match_rev.get(&n).copied().unwrap_or(0);
            let claim = names_a
                .get(&b)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let claim = short_name(&claim, 60);
            format!(
                "{}{:#x}  ← {:#x}  [WRONG]  target={}  base_claim={}",
                prefix, n, b, nm, claim
            )
        }
        NodeStatus::Missed => format!("{}{:#x}  <unmatched>  {}", prefix, n, nm),
        NodeStatus::Import => format!("{}{:#x}  [import/external]", prefix, n),
    }
}

/// Anchor mode entry point. Resolves --anchor patterns to (base, target)
/// address pairs, computes path-union subgraphs on each side, renders one
/// combined .dot/.svg + a sidecar match-map.txt with anchor reachability.
#[allow(clippy::too_many_arguments)]
fn render_anchor_network(
    patterns: &[String],
    by_name_a: &FxHashMap<&str, Vec<u64>>,
    by_name_b: &FxHashMap<&str, Vec<u64>>,
    funcs1_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    funcs2_by_ep: &FxHashMap<u64, &FunctionAnalysis>,
    callers_a: &FxHashMap<u64, Vec<u64>>,
    callers_b: &FxHashMap<u64, Vec<u64>>,
    alg_match: &FxHashMap<u64, u64>,
    alg_match_rev: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
    iat_a: &HashMap<u64, String>,
    iat_b: &HashMap<u64, String>,
    cache: &MatchesCache,
    args: &Args,
) -> Result<ReportRow> {
    // Resolve patterns. For each pattern, every PDB name matching it AND
    // present in BOTH binaries contributes one anchor pair.
    let mut anchor_pairs: Vec<(String, u64, u64)> = Vec::new();
    let mut by_pattern: Vec<(String, usize)> = Vec::new();
    for pat in patterns {
        let mut hits: Vec<&str> = by_name_a
            .keys()
            .copied()
            .filter(|n| n.contains(pat.as_str()) && by_name_b.contains_key(*n))
            .collect();
        hits.sort();
        let mut count = 0usize;
        for name in hits {
            let addr_a = by_name_a[name][0];
            let addr_b = by_name_b[name][0];
            if !funcs1_by_ep.contains_key(&addr_a) || !funcs2_by_ep.contains_key(&addr_b) {
                continue;
            }
            anchor_pairs.push((name.to_string(), addr_a, addr_b));
            count += 1;
        }
        by_pattern.push((pat.clone(), count));
    }

    if anchor_pairs.is_empty() {
        return Err(anyhow!(
            "no anchor patterns matched a name present in both binaries"
        ));
    }

    // Dedup by address — multiple PDB names (e.g., mangled + demangled
    // forms of the same symbol) often resolve to the same address; the
    // path-finding only cares about unique addresses. The anchor_pairs list
    // is kept un-deduped so the match-map sidebar shows every name alias.
    let anchor_addrs_a: FxHashSet<u64> = anchor_pairs.iter().map(|(_, a, _)| *a).collect();
    let anchor_addrs_b: FxHashSet<u64> = anchor_pairs.iter().map(|(_, _, b)| *b).collect();
    let anchors_a: Vec<u64> = {
        let mut v: Vec<u64> = anchor_addrs_a.iter().copied().collect();
        v.sort_unstable();
        v
    };
    let anchors_b: Vec<u64> = {
        let mut v: Vec<u64> = anchor_addrs_b.iter().copied().collect();
        v.sort_unstable();
        v
    };

    eprintln!(
        "anchor mode: {} anchor pairs from {} pattern(s)",
        anchor_pairs.len(),
        patterns.len()
    );
    for (pat, count) in &by_pattern {
        eprintln!("  '{}' → {} anchor(s)", pat, count);
    }

    let (nodes_a, edges_a, reach_a) = compute_anchor_subgraph(
        &anchors_a,
        funcs1_by_ep,
        callers_a,
        &args.direction,
        args.max_path_hops,
    );
    let (nodes_b, edges_b, reach_b) = compute_anchor_subgraph(
        &anchors_b,
        funcs2_by_ep,
        callers_b,
        &args.direction,
        args.max_path_hops,
    );

    let pair_total = anchors_a.len() * anchors_a.len().saturating_sub(1);
    eprintln!(
        "  base: {} nodes, {} reachable anchor pairs / {}",
        nodes_a.len(),
        reach_a.len(),
        pair_total
    );
    eprintln!(
        "  target: {} nodes, {} reachable anchor pairs / {}",
        nodes_b.len(),
        reach_b.len(),
        pair_total
    );

    // Classify visible nodes.
    let mut statuses_a: FxHashMap<u64, NodeStatus> = FxHashMap::default();
    let mut statuses_b: FxHashMap<u64, NodeStatus> = FxHashMap::default();
    let mut correct = 0usize;
    let mut wrong = 0usize;
    let mut missed = 0usize;
    let anchor_set_a: FxHashSet<u64> = anchors_a.iter().copied().collect();
    let anchor_set_b: FxHashSet<u64> = anchors_b.iter().copied().collect();
    for &n in &nodes_a {
        let s = classify_base(n, funcs1_by_ep, iat_a, alg_match, names_a, names_b);
        // Stats include intermediates (not anchors) — anchors are reported
        // separately in the match-map.
        if !anchor_set_a.contains(&n) {
            match s {
                NodeStatus::Correct => correct += 1,
                NodeStatus::Wrong => wrong += 1,
                NodeStatus::Missed => missed += 1,
                _ => {}
            }
        }
        statuses_a.insert(n, s);
    }
    for &n in &nodes_b {
        let s = classify_target(n, funcs2_by_ep, iat_b, alg_match_rev, names_a, names_b);
        statuses_b.insert(n, s);
    }

    // ---- Render dot ----
    let pattern_summary = patterns.join(", ");
    let mut dot = String::new();
    writeln!(dot, "digraph G {{").unwrap();
    writeln!(dot, "  rankdir=TB;").unwrap();
    writeln!(dot, "  compound=true;").unwrap();
    writeln!(
        dot,
        "  node [shape=box, style=\"filled,rounded\", fontname=Helvetica, fontsize=10];"
    )
    .unwrap();
    writeln!(dot, "  edge [color=\"#666666\", arrowsize=0.7];").unwrap();
    writeln!(dot, "  labelloc=\"t\"; fontsize=12;").unwrap();
    writeln!(
        dot,
        "  label=\"anchor network: {}\\n{} anchors  direction={}  max-path-hops={}\";",
        dot_escape(&short_name(&pattern_summary, 80)),
        anchor_pairs.len(),
        args.direction,
        args.max_path_hops
    )
    .unwrap();

    render_cluster(
        &mut dot,
        'a',
        &format!(
            "BASE  ({} nodes, {}/{} anchor pairs reachable)",
            nodes_a.len(),
            reach_a.len(),
            pair_total
        ),
        &nodes_a,
        &edges_a,
        &statuses_a,
        names_a,
        iat_a,
        &cache.synth_a,
        &anchor_set_a,
        false,
    );
    render_cluster(
        &mut dot,
        'b',
        &format!(
            "TARGET  ({} nodes, {}/{} anchor pairs reachable)",
            nodes_b.len(),
            reach_b.len(),
            pair_total
        ),
        &nodes_b,
        &edges_b,
        &statuses_b,
        names_b,
        iat_b,
        &cache.synth_b,
        &anchor_set_b,
        false,
    );
    write_legend(&mut dot);
    writeln!(dot, "}}").unwrap();

    let stem = "anchor-network".to_string();
    let dot_path = args.out.join(format!("{}.dot", stem));
    fs::write(&dot_path, &dot)?;

    if args.svg {
        let svg_path = args.out.join(format!("{}.svg", stem));
        let res = std::process::Command::new("dot")
            .arg("-Tsvg")
            .arg(&dot_path)
            .arg("-o")
            .arg(&svg_path)
            .status();
        match res {
            Ok(s) if s.success() => {}
            Ok(s) => eprintln!("  dot exited {}: {}", s, dot_path.display()),
            Err(e) => eprintln!("  dot invocation failed: {}", e),
        }
    }

    if !args.no_match_map {
        write_anchor_map(
            &args.out.join(format!("{}.match-map.txt", stem)),
            &anchor_pairs,
            &anchors_a,
            &anchors_b,
            &nodes_a,
            &nodes_b,
            &statuses_a,
            &statuses_b,
            &reach_a,
            &reach_b,
            &anchor_set_a,
            &anchor_set_b,
            alg_match,
            alg_match_rev,
            names_a,
            names_b,
        )?;
    }

    Ok(ReportRow {
        name: format!("anchor network ({} anchors)", anchor_pairs.len()),
        base_count: nodes_a.len(),
        target_count: nodes_b.len(),
        correct,
        wrong,
        missed,
        file_stem: stem,
    })
}

#[allow(clippy::too_many_arguments)]
fn write_anchor_map(
    path: &Path,
    anchor_pairs: &[(String, u64, u64)],
    anchors_a: &[u64],
    _anchors_b: &[u64],
    nodes_a: &FxHashSet<u64>,
    nodes_b: &FxHashSet<u64>,
    statuses_a: &FxHashMap<u64, NodeStatus>,
    statuses_b: &FxHashMap<u64, NodeStatus>,
    reach_a: &[(u64, u64, usize)],
    reach_b: &[(u64, u64, usize)],
    anchor_set_a: &FxHashSet<u64>,
    anchor_set_b: &FxHashSet<u64>,
    alg_match: &FxHashMap<u64, u64>,
    alg_match_rev: &FxHashMap<u64, u64>,
    names_a: &HashMap<u64, Vec<String>>,
    names_b: &HashMap<u64, Vec<String>>,
) -> Result<()> {
    let mut s = String::new();
    writeln!(s, "anchor network").unwrap();
    writeln!(s).unwrap();
    writeln!(s, "ANCHORS ({} pairs):", anchor_pairs.len()).unwrap();
    for (name, a, b) in anchor_pairs {
        let nm = short_name(name, 60);
        writeln!(s, "  {}  base={:#x}  target={:#x}", nm, a, b).unwrap();
    }
    writeln!(s).unwrap();

    // Anchor reachability: which anchor pairs are connected on each side?
    let total = anchors_a.len() * anchors_a.len().saturating_sub(1);
    writeln!(
        s,
        "REACHABILITY ({}/{} pairs on base, {}/{} on target):",
        reach_a.len(),
        total,
        reach_b.len(),
        total
    )
    .unwrap();
    let render_reach = |buf: &mut String,
                        label: &str,
                        reach: &[(u64, u64, usize)],
                        names: &HashMap<u64, Vec<String>>| {
        writeln!(buf, "  {}:", label).unwrap();
        let mut sorted = reach.to_vec();
        sorted.sort_unstable_by_key(|(_, _, d)| *d);
        for (from, to, d) in sorted {
            let nf = names
                .get(&from)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let nt = names
                .get(&to)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            writeln!(
                buf,
                "    [{}-hop] {} → {}",
                d,
                short_name(&nf, 50),
                short_name(&nt, 50)
            )
            .unwrap();
        }
    };
    render_reach(&mut s, "BASE", reach_a, names_a);
    render_reach(&mut s, "TARGET", reach_b, names_b);
    writeln!(s).unwrap();

    // Per-side per-node breakdown so user can spot wrong-claim or unmatched
    // intermediates.
    writeln!(s, "BASE neighborhood ({} nodes):", nodes_a.len()).unwrap();
    let mut sa: Vec<u64> = nodes_a.iter().copied().collect();
    sa.sort_unstable();
    for n in sa {
        let st = statuses_a.get(&n).copied().unwrap_or(NodeStatus::Missed);
        writeln!(
            s,
            "{}",
            format_base_node_line(
                n,
                anchor_set_a.contains(&n),
                st,
                alg_match,
                names_a,
                names_b
            )
        )
        .unwrap();
    }
    writeln!(s).unwrap();
    writeln!(s, "TARGET neighborhood ({} nodes):", nodes_b.len()).unwrap();
    let mut sb: Vec<u64> = nodes_b.iter().copied().collect();
    sb.sort_unstable();
    for n in sb {
        let st = statuses_b.get(&n).copied().unwrap_or(NodeStatus::Missed);
        writeln!(
            s,
            "{}",
            format_target_node_line(
                n,
                anchor_set_b.contains(&n),
                st,
                alg_match_rev,
                names_a,
                names_b
            )
        )
        .unwrap();
    }

    fs::write(path, s)?;
    Ok(())
}

fn write_index(out: &Path, rows: &[ReportRow], svg: bool) -> Result<()> {
    let mut md = String::new();
    writeln!(md, "# graph_diff report").unwrap();
    writeln!(md).unwrap();
    writeln!(
        md,
        "{} graphs. correct/wrong/missed counts exclude the focal node and import nodes.",
        rows.len()
    )
    .unwrap();
    writeln!(md).unwrap();
    writeln!(
        md,
        "| name | base | correct | wrong | missed | target | dot | svg | match-map |"
    )
    .unwrap();
    writeln!(md, "|---|---:|---:|---:|---:|---:|---|---|---|").unwrap();
    for r in rows {
        let svg_cell = if svg {
            format!("[svg]({}.svg)", r.file_stem)
        } else {
            "—".into()
        };
        writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} | [dot]({}.dot) | {} | [txt]({}.match-map.txt) |",
            r.name,
            r.base_count,
            r.correct,
            r.wrong,
            r.missed,
            r.target_count,
            r.file_stem,
            svg_cell,
            r.file_stem,
        )
        .unwrap();
    }
    fs::write(out.join("index.md"), md)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.dump_shared
        && args.symbol_set.is_none()
        && args.patterns.is_empty()
        && args.addrs.is_empty()
        && args.anchors.is_empty()
    {
        return Err(anyhow!(
            "must pass at least one --pattern, --addr, --anchor, --symbol-set, or --dump-shared"
        ));
    }
    if !args.anchors.is_empty() && (!args.patterns.is_empty() || !args.addrs.is_empty()) {
        return Err(anyhow!(
            "--anchor is mutually exclusive with --pattern/--addr"
        ));
    }

    eprintln!("loading PEs...");
    let (pe1, funcs1) = analyze(&args.base)?;
    let (pe2, funcs2) = analyze(&args.target)?;
    eprintln!(
        "  base: {} functions, target: {} functions",
        funcs1.len(),
        funcs2.len()
    );

    eprintln!("loading PDBs...");
    let names_a = load_pdb_names(&args.base, &pe1)?;
    let names_b = load_pdb_names(&args.target, &pe2)?;
    eprintln!(
        "  base: {} addrs named, target: {} addrs named",
        names_a.len(),
        names_b.len()
    );

    eprintln!("loading match cache...");
    let cache = parse_matches_cache(&args.matches_cache)?;
    eprintln!(
        "  {} matches, {} synth_a, {} synth_b",
        cache.matches.len(),
        cache.synth_a.len(),
        cache.synth_b.len()
    );

    let funcs1_by_ep: FxHashMap<u64, &FunctionAnalysis> =
        funcs1.iter().map(|f| (f.entry_point, f)).collect();
    let funcs2_by_ep: FxHashMap<u64, &FunctionAnalysis> =
        funcs2.iter().map(|f| (f.entry_point, f)).collect();
    let callers_a = build_callers(&funcs1);
    let callers_b = build_callers(&funcs2);

    let iat_a = pe1.iat()?;
    let iat_b = pe2.iat()?;

    let alg_match_rev: FxHashMap<u64, u64> = cache.matches.iter().map(|(&a, &b)| (b, a)).collect();

    let mut by_name_a: FxHashMap<&str, Vec<u64>> = FxHashMap::default();
    for (addr, ns) in &names_a {
        for s in ns {
            by_name_a.entry(s.as_str()).or_default().push(*addr);
        }
    }
    let mut by_name_b: FxHashMap<&str, Vec<u64>> = FxHashMap::default();
    for (addr, ns) in &names_b {
        for s in ns {
            by_name_b.entry(s.as_str()).or_default().push(*addr);
        }
    }

    if args.dump_shared {
        // Discovery dump: every PDB name present in both binaries, with the
        // algorithm's verdict on it. Tab-separated for awk/sort/grep
        // pipelines. Written to stdout; pipe to a file if you want to keep it.
        println!("status\tname\tbase_addr\ttarget_addr\tbase_callees\tbase_callers\talg_target");
        let mut shared: Vec<&str> = by_name_a
            .keys()
            .copied()
            .filter(|n| by_name_b.contains_key(*n))
            .collect();
        shared.sort_unstable();
        for name in shared {
            let addr_a = by_name_a[name][0];
            let addr_b = by_name_b[name][0];
            let status = match cache.matches.get(&addr_a) {
                None => "missed",
                Some(&t) if t == addr_b => "correct",
                Some(&t) => match names_overlap(names_a.get(&addr_a), names_b.get(&t)) {
                    // Multi-symbol functions: an alias of `name` may overlap
                    // with whatever the algorithm picked, in which case it's
                    // "correct" by the any-name-overlap rule.
                    Some(true) => "correct",
                    _ => "wrong",
                },
            };
            let base_callees = funcs1_by_ep
                .get(&addr_a)
                .map(|f| f.calls.len())
                .unwrap_or(0);
            let base_callers = callers_a.get(&addr_a).map(|v| v.len()).unwrap_or(0);
            let alg_target = cache.matches.get(&addr_a).copied().unwrap_or(0);
            // Tabs in symbol names don't happen; safe as TSV.
            println!(
                "{}\t{}\t{:#x}\t{:#x}\t{}\t{}\t{:#x}",
                status, name, addr_a, addr_b, base_callees, base_callers, alg_target
            );
        }
        return Ok(());
    }

    // --symbol-set: iterate sections.
    if let Some(path) = &args.symbol_set {
        let sections = parse_symbol_set(path)?;
        eprintln!("symbol-set: {} sections", sections.len());
        if args.analyze_paths {
            return analyze_paths(
                &sections,
                &by_name_a,
                &by_name_b,
                &funcs1_by_ep,
                &funcs2_by_ep,
                &callers_a,
                &callers_b,
                &cache.matches,
                &alg_match_rev,
                &names_a,
                &names_b,
                &iat_a,
                &iat_b,
                &args.direction,
                args.max_path_hops,
            );
        }
        return Err(anyhow!(
            "--symbol-set without --analyze-paths is not yet implemented (rendering pending)"
        ));
    }

    fs::create_dir_all(&args.out)?;
    let mut rows: Vec<ReportRow> = Vec::new();

    // --anchor: anchor-network mode. One combined graph per binary pair.
    if !args.anchors.is_empty() {
        let row = render_anchor_network(
            &args.anchors,
            &by_name_a,
            &by_name_b,
            &funcs1_by_ep,
            &funcs2_by_ep,
            &callers_a,
            &callers_b,
            &cache.matches,
            &alg_match_rev,
            &names_a,
            &names_b,
            &iat_a,
            &iat_b,
            &cache,
            &args,
        )?;
        rows.push(row);
        write_index(&args.out, &rows, args.svg)?;
        eprintln!(
            "done. {} graphs written to {}",
            rows.len(),
            args.out.display()
        );
        return Ok(());
    }

    // --pattern: any name in BOTH binaries; renderable means the canonical
    // (first) addr on each side is in the analyzed function set.
    for pat in &args.patterns {
        let mut hits: Vec<&str> = by_name_a
            .keys()
            .copied()
            .filter(|n| n.contains(pat.as_str()) && by_name_b.contains_key(*n))
            .collect();
        hits.sort();
        eprintln!("pattern '{}': {} matching shared names", pat, hits.len());
        for name in hits.iter().take(args.pattern_limit) {
            let addr_a = by_name_a[name][0];
            let addr_b = by_name_b[name][0];
            if !funcs1_by_ep.contains_key(&addr_a) || !funcs2_by_ep.contains_key(&addr_b) {
                eprintln!("  skip '{}' (addr not in funcs)", name);
                continue;
            }
            eprintln!(
                "  rendering '{}'  base={:#x}  target={:#x}",
                name, addr_a, addr_b
            );
            let row = render_pair(
                name,
                addr_a,
                addr_b,
                &funcs1_by_ep,
                &funcs2_by_ep,
                &callers_a,
                &callers_b,
                &cache.matches,
                &alg_match_rev,
                &names_a,
                &names_b,
                &iat_a,
                &iat_b,
                &cache,
                &args,
            )?;
            rows.push(row);
        }
    }

    // --addr: pin a base address; pair via the match cache.
    for &addr in &args.addrs {
        let Some(&target) = cache.matches.get(&addr) else {
            eprintln!(
                "  --addr {:#x}: no algorithm match in cache, skipping",
                addr
            );
            continue;
        };
        if !funcs1_by_ep.contains_key(&addr) || !funcs2_by_ep.contains_key(&target) {
            eprintln!("  --addr {:#x}: addr not in analyzed funcs, skipping", addr);
            continue;
        }
        let name = names_a
            .get(&addr)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| format!("addr_{:x}", addr));
        eprintln!(
            "  rendering --addr {:#x} -> target {:#x} ({})",
            addr, target, name
        );
        let row = render_pair(
            &name,
            addr,
            target,
            &funcs1_by_ep,
            &funcs2_by_ep,
            &callers_a,
            &callers_b,
            &cache.matches,
            &alg_match_rev,
            &names_a,
            &names_b,
            &iat_a,
            &iat_b,
            &cache,
            &args,
        )?;
        rows.push(row);
    }

    write_index(&args.out, &rows, args.svg)?;
    eprintln!(
        "done. {} graphs written to {}",
        rows.len(),
        args.out.display()
    );
    Ok(())
}
