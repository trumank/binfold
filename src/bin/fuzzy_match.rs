//! Hack: feeds binfold's x86 analysis into grapnel's MinHash/LSH engine.
//!
//! Builds one Graph<u64> per binary (nodes = functions, edges = direct calls)
//! and runs `match_graphs` to produce a map of base-binary function addresses
//! to target-binary function addresses.

use anyhow::Result;
use binfold::fn_ptr_index::{FnPtrIndex, find_fn_ptr_sites};
use binfold::mmap_source::MmapSource;
use binfold::pdb_analyzer;
use binfold::pdb_writer::{self, extract_pdb_info};
use binfold::pe_loader::{FunctionAnalysis, PeLoader};
use binfold::warp::read_string_data;
use clap::{Parser, ValueEnum};
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
    #[arg(long, value_enum, default_value_t = BundleDir::Both)]
    bundle: BundleDir,

    /// Restrict which feature categories get propagated through bundling.
    /// Comma-separated subset of: bigram, import, string, const, blkcount,
    /// callcount. Default `import,string,const` is the asymmetric-bundling
    /// sweet spot: carries cross-compiler-stable identity through the
    /// neighborhood while keeping bigrams local. Set to "all" (any
    /// nonexistent category sentinel) is not supported — pass an empty value
    /// or omit the flag for the legacy "all categories propagate" behavior.
    #[arg(long, value_delimiter = ',', default_value = "import,string,const")]
    bundle_features: Option<Vec<FeatureCategory>>,

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
    /// their *certified* call topology. **Default 3** with soft re-evaluation
    /// (default ON): metrics monotonically improve through iter=5+ — the
    /// pass-3 regression that capped this at 2 under the lock rule is gone.
    /// Use `--iterations 2` to match the prior lock-rule-era default.
    #[arg(long, default_value_t = 5)]
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

    /// Write a PDB for the target binary, populated with symbol names from
    /// the base binary's PDB for each matched pair. Reads names from
    /// `<base>.pdb` and emits a PDB whose debug GUID/age/timestamp match the
    /// target binary so a debugger will load it automatically.
    #[arg(long)]
    generate_pdb: Option<PathBuf>,

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

    /// Disable soft re-evaluation. With soft re-eval (default ON), in
    /// passes after the first a new pair (a, b) can overwrite an existing
    /// pair if the new similarity exceeds the old by at least
    /// `--revise-margin`. With this flag, falls back to the original
    /// lock-existing-pairs rule (first pass to confirm wins). Soft re-eval
    /// monotonically improves both precision and recall through iter=5+;
    /// the lock rule had a recall regression at iter=3 that capped useful
    /// iterations at 2.
    #[arg(long)]
    no_revision: bool,

    /// Margin for soft re-evaluation. A new pair must beat an existing
    /// pair's similarity by at least this much to overwrite. Empirically
    /// 0.0 (any improvement wins) gives the best metrics — both precision
    /// and recall — because the lock rule was preserving more wrong
    /// answers than correct revisions would introduce. Higher = more
    /// conservative; less revision activity per pass.
    #[arg(long, default_value_t = 0.0)]
    revise_margin: f64,

    /// After --validate, also run achievability analysis: for every PDB
    /// ground-truth pair (a, b) where the same name exists in both
    /// binaries, compute the weighted Jaccard between their feature sets
    /// (with the FINAL synth maps from the run). Histograms the J
    /// distribution and cross-tabs against the matcher's actual outcome
    /// (correct/wrong/missed). Tells you which pairs are structurally
    /// invisible vs which the matcher actively missed.
    #[arg(long)]
    measure_achievability: bool,

    /// Asymmetric Phase 4 hub gate: skip propagation only when BOTH sides
    /// exceed `--max-degree` (default symmetric: skip when EITHER side
    /// exceeds). Asymmetric accepts paths where one side is hub-inflated
    /// by inlining asymmetry but the other isn't — the cross-compiler
    /// case where target inlines more than base. Predicted to recover
    /// pairs in [0.2, 0.5) propagation zone (per achievability data).
    #[arg(long)]
    asymmetric_hub_gate: bool,

    /// Phase 4 size-mismatch ratio. Skip a candidate pair when
    /// max(size_a, size_b) / min(size_a, size_b) exceeds this. The original
    /// grapnel default 2.0 was calibrated for symmetric same-compiler
    /// cases; cross-compiler inlining routinely produces 3-5x size
    /// differences. Per the trace stats, the 2.0 cap blocked ~800k pairs/pass
    /// (~160× more than the hub gate). Default 4.0: gives +0.79pp recall
    /// alone on 505S/505SC; combines with `--fn-ptr-peer-radius >= 5` and
    /// `--iterations >= 3` for the highest known recall regimes. Beyond 5.0
    /// is non-monotonic on this fixture (extra admitted pairs introduce
    /// wrong matches that perturb pass-2's synth context).
    #[arg(long, default_value_t = 4.0)]
    size_mismatch_ratio: f32,

    /// Disable RO-data function-pointer features (FnPtrRefBucket +
    /// FnPtrPeer). Provided for ablation only — these features
    /// specifically target virtual functions, which dispatch indirectly
    /// and therefore have no `func.calls` entries pointing at them
    /// (i.e. SyntCallee never propagates *into* them from a parent).
    #[arg(long)]
    no_fn_ptr: bool,

    /// Maximum |offset| (in pointer-sized slots) for FnPtrPeer features.
    /// For each RO-data site of F, peers at offsets ±1..=N whose function
    /// has a synth ID from a prior match pass are emitted. Weight decays
    /// geometrically with |offset|: 16 / 8 / 4 / 2. Default 10: empirically
    /// strict-Pareto-dominates radius=3 and radius=5 on 505S/505SC (45.85%
    /// recall / 68.92% precision at iter=3). Past 15, recall drops because
    /// peer features start crossing vtable boundaries — entries from
    /// adjacent unrelated vtables get treated as peers, polluting Jaccard.
    #[arg(long, default_value_t = 10)]
    fn_ptr_peer_radius: u8,

    // --- per-feature weight overrides (None = use baked-in default) ---
    /// Override weight for `Feat::Bigram` (default 1).
    #[arg(long)]
    w_bigram: Option<u32>,
    /// Override weight for `Feat::Import` (default 8).
    #[arg(long)]
    w_import: Option<u32>,
    /// Override weight for `Feat::StringLit` (default 8).
    #[arg(long)]
    w_string: Option<u32>,
    /// Override weight for `Feat::Const` (default 8).
    #[arg(long)]
    w_const: Option<u32>,
    /// Override weight for `Feat::BlockCountBucket` (default 4).
    #[arg(long)]
    w_block_count: Option<u32>,
    /// Override weight for `Feat::CallCountBucket` (default 4).
    #[arg(long)]
    w_call_count: Option<u32>,
    /// Override weight for `Feat::Nbr` at depth=1 (default 2).
    #[arg(long)]
    w_nbr_d1: Option<u32>,
    /// Override weight for `Feat::Nbr` at depth>=2 (default 1).
    #[arg(long)]
    w_nbr_deep: Option<u32>,
    /// Override weight for `Feat::SyntCallee` at depth=1 (default 16).
    #[arg(long)]
    w_synt_d1: Option<u32>,
    /// Override weight for `Feat::SyntCallee` at depth=2 (default 8).
    #[arg(long)]
    w_synt_d2: Option<u32>,
    /// Override weight for `Feat::SyntCallee` at depth=3 (default 4).
    #[arg(long)]
    w_synt_d3: Option<u32>,
    /// Override weight for `Feat::SyntCallee` at depth>=4 (default 2).
    #[arg(long)]
    w_synt_deep: Option<u32>,
    /// Override weight for `Feat::FnPtrRefBucket` (default 4).
    #[arg(long)]
    w_fnptr_ref: Option<u32>,
    /// Override weight for `Feat::FnPtrPeer` at |offset|=1 (default 16).
    #[arg(long)]
    w_fnptr_peer_d1: Option<u32>,
    /// Override weight for `Feat::FnPtrPeer` at |offset|=2 (default 8).
    #[arg(long)]
    w_fnptr_peer_d2: Option<u32>,
    /// Override weight for `Feat::FnPtrPeer` at |offset|=3 (default 4).
    #[arg(long)]
    w_fnptr_peer_d3: Option<u32>,
    /// Override weight for `Feat::FnPtrPeer` at |offset|>=4 (default 2).
    #[arg(long)]
    w_fnptr_peer_deep: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BundleDir {
    Callees,
    Callers,
    Both,
}

/// Display + bundling categories for `Feat` variants. The user-bundleable
/// subset (everything except `Nbr` and `Synt`) is exposed to clap via
/// `ValueEnum`; the two `#[value(skip)]` variants exist only for the
/// inspector's per-category display and never appear in a user-supplied
/// `--bundle-features` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, ValueEnum)]
enum FeatureCategory {
    Bigram,
    Import,
    String,
    Const,
    #[value(name = "blkcount")]
    BlkCount,
    #[value(name = "callcount")]
    CallCount,
    #[value(skip)]
    Nbr,
    #[value(skip)]
    Synt,
    #[value(skip)]
    FnPtr,
}

impl FeatureCategory {
    /// Short label used in inspector column headers (≤9 chars wide).
    fn label(self) -> &'static str {
        match self {
            FeatureCategory::Bigram => "bigram",
            FeatureCategory::Import => "import",
            FeatureCategory::String => "string",
            FeatureCategory::Const => "const",
            FeatureCategory::BlkCount => "blkcount",
            FeatureCategory::CallCount => "callcount",
            FeatureCategory::Nbr => "nbr",
            FeatureCategory::Synt => "synt",
            FeatureCategory::FnPtr => "fnptr",
        }
    }
}

/// All knobs that flow through feature extraction, graph build, and the
/// inspectors. Constructed once via `FeatureConfig::from_args`, then passed
/// by reference. Adding a new feature-extraction knob = add a field here,
/// not a parameter on every signature.
#[derive(Clone)]
struct FeatureConfig {
    use_bigrams: bool,
    hops: usize,
    /// Shared between bundling BFS and multi-hop SyntCallee BFS — same
    /// "don't recurse through hubs" semantics in both places.
    hub_degree: usize,
    bundle_dir: BundleDir,
    bundle_filter: Option<FxHashSet<FeatureCategory>>,
    synt_depth: u8,
    use_fn_ptr: bool,
    fn_ptr_peer_radius: u8,
    weights: WeightConfig,
}

impl FeatureConfig {
    fn from_args(args: &Args) -> Self {
        FeatureConfig {
            use_bigrams: !args.no_bigrams,
            hops: args.hops,
            hub_degree: args.hub_degree,
            bundle_dir: args.bundle,
            bundle_filter: args
                .bundle_features
                .as_ref()
                .map(|v| v.iter().copied().collect()),
            synt_depth: args.synt_depth,
            use_fn_ptr: !args.no_fn_ptr,
            fn_ptr_peer_radius: args.fn_ptr_peer_radius,
            weights: WeightConfig::from_args(args),
        }
    }
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
    /// Number of times F's address appears in RO data (vtables, RTTI,
    /// dispatch tables), log-bucketed. Only emitted when at least one
    /// reference exists — otherwise this feature would collapse every
    /// non-virtual function into bucket 0 and produce a degenerate
    /// "everyone matches" signal. Stable across compilers: the
    /// reference count is a property of the class hierarchy, not codegen.
    FnPtrRefBucket(u32),
    /// Synthetic peer-identity from RO-data grid adjacency. For each
    /// site `(data_addr, F)` and signed slot offset Δ within the peer
    /// radius, if the function at `data_addr + Δ * ptr_size` has a synth
    /// ID `S` from a prior match pass, emit `FnPtrPeer { offset: Δ, hash: S }`.
    /// Vtable-adjacency analog of SyntCallee — gives virtual functions
    /// a topology even though `func.calls` never lists them (dispatch
    /// is indirect through `call [reg+off]`).
    FnPtrPeer { offset: i8, hash: u64 },
}

/// Per-feature-category weight overrides. All weights configurable via
/// CLI flags (defaults baked here). Plumbed through `extract_features` —
/// no globals — so a sweep can run multiple configs in one process if
/// needed.
#[derive(Debug, Clone, Copy)]
struct WeightConfig {
    bigram: u32,
    import: u32,
    string_lit: u32,
    const_: u32,
    block_count: u32,
    call_count: u32,
    nbr_d1: u32,
    nbr_deep: u32,
    synt_d1: u32,
    synt_d2: u32,
    synt_d3: u32,
    synt_deep: u32,
    fnptr_ref: u32,
    fnptr_peer_d1: u32,
    fnptr_peer_d2: u32,
    fnptr_peer_d3: u32,
    fnptr_peer_deep: u32,
}

impl Default for WeightConfig {
    fn default() -> Self {
        Self {
            // Compiler-coupled identity signal. Many bigrams per function
            // (median 25-100), so even at weight=1 they dominate by count
            // when no other features exist. Sweep showed weight≥2 hurts
            // recall significantly (compiler-coupled noise compounds).
            bigram: 1,
            // Compiler-stable identity. Few per function (often 0-3), so
            // weight them up so a single matching string/import/constant
            // can anchor a function whose bigrams have diverged.
            //
            // string_lit raised to 64 (was 16, originally 8). Sweep showed
            // strings are the strongest cross-compiler-stable signal —
            // bytewise-identical across compilers, low collision rate
            // (most strings are unique). Successive bumps strict-Pareto-
            // improved on 505S/505SC: 8→16 was +0.88pp recall +0.36pp
            // prec; 16→64 added another +0.15pp recall +0.56pp prec.
            // Beyond 64 saturates.
            //
            // const lowered to 4 (was 8). Constants collide on common
            // values (powers of 2, struct sizes, hash multipliers), so
            // overweighting them creates false-positive Jaccard signal.
            // 8→4 was net positive (+0.30pp recall, neutral precision).
            // 16 hurt recall by 2pp.
            import: 8,
            string_lit: 64,
            const_: 4,
            // Coarse shape — always present, weakly distinctive. Lowered
            // from 4 to 1: empirical strict Pareto improvement (~0pp
            // recall, +1.65pp precision) — the 4-weight was overweighting
            // a feature most pairs share by chance, polluting Jaccard.
            block_count: 1,
            call_count: 1,
            // Neighborhood features decay with depth: 1-hop is more
            // informative than further hops.
            nbr_d1: 2,
            nbr_deep: 1,
            // Certified cross-binary identity from a previous match pass.
            // Strongest signal at depth=1 (direct callee), geometric decay.
            // Doubling all weights (32/16/8/4) lifts recall by +1.49pp at
            // -1.45pp precision — kept at the original schedule because
            // the precision cost is too steep for the default; users who
            // want max recall can override via --w-synt-d1 32 etc.
            synt_d1: 16,
            synt_d2: 8,
            synt_d3: 4,
            synt_deep: 2,
            // Coarse shape — vtable reference count.
            fnptr_ref: 4,
            // Certified peer identity through vtable adjacency. Final
            // schedule 256/64/16/4 was the empirical recall ceiling on
            // 505S/505SC: pushing d1 from 32→128→256 lifted recall in
            // +1.93pp + 0.48pp steps before saturating at 256. The sharp
            // shape (steep decay vs gentle 256/128/64/32) wins because
            // peers at radius 6+ increasingly cross vtable boundaries
            // (encounter unrelated functions adjacent to the target's
            // vtable in `.rdata`); high weight on those polluted distant
            // peers hurts. Sharp decay correctly trusts close vtable
            // adjacency strongly while ignoring noisy distant slots.
            //
            // Trade vs the prior 32/16/8/4 default: +2.41pp recall for
            // -0.64pp precision when paired with iter=5 — recall-favoring
            // but still net positive overall (recall ceiling 71%, this
            // takes us to 51.77% = 72.9% of achievable). Users wanting
            // precision-favored defaults can override back to 32/16/8/4.
            fnptr_peer_d1: 256,
            fnptr_peer_d2: 64,
            fnptr_peer_d3: 16,
            fnptr_peer_deep: 4,
        }
    }
}

impl WeightConfig {
    fn from_args(args: &Args) -> Self {
        let d = WeightConfig::default();
        WeightConfig {
            bigram: args.w_bigram.unwrap_or(d.bigram),
            import: args.w_import.unwrap_or(d.import),
            string_lit: args.w_string.unwrap_or(d.string_lit),
            const_: args.w_const.unwrap_or(d.const_),
            block_count: args.w_block_count.unwrap_or(d.block_count),
            call_count: args.w_call_count.unwrap_or(d.call_count),
            nbr_d1: args.w_nbr_d1.unwrap_or(d.nbr_d1),
            nbr_deep: args.w_nbr_deep.unwrap_or(d.nbr_deep),
            synt_d1: args.w_synt_d1.unwrap_or(d.synt_d1),
            synt_d2: args.w_synt_d2.unwrap_or(d.synt_d2),
            synt_d3: args.w_synt_d3.unwrap_or(d.synt_d3),
            synt_deep: args.w_synt_deep.unwrap_or(d.synt_deep),
            fnptr_ref: args.w_fnptr_ref.unwrap_or(d.fnptr_ref),
            fnptr_peer_d1: args.w_fnptr_peer_d1.unwrap_or(d.fnptr_peer_d1),
            fnptr_peer_d2: args.w_fnptr_peer_d2.unwrap_or(d.fnptr_peer_d2),
            fnptr_peer_d3: args.w_fnptr_peer_d3.unwrap_or(d.fnptr_peer_d3),
            fnptr_peer_deep: args.w_fnptr_peer_deep.unwrap_or(d.fnptr_peer_deep),
        }
    }

    /// Compute the weight for a given Feat under this config. Pure
    /// function — no I/O, no globals.
    fn weight_for(&self, feat: &Feat) -> u32 {
        match feat {
            Feat::Bigram(_) => self.bigram,
            Feat::Import(_) => self.import,
            Feat::StringLit(_) => self.string_lit,
            Feat::Const(_) => self.const_,
            Feat::BlockCountBucket(_) => self.block_count,
            Feat::CallCountBucket(_) => self.call_count,
            Feat::Nbr { depth, .. } => match depth {
                1 => self.nbr_d1,
                _ => self.nbr_deep,
            },
            Feat::SyntCallee { depth, .. } => match depth {
                1 => self.synt_d1,
                2 => self.synt_d2,
                3 => self.synt_d3,
                _ => self.synt_deep,
            },
            Feat::FnPtrRefBucket(_) => self.fnptr_ref,
            Feat::FnPtrPeer { offset, .. } => match offset.unsigned_abs() {
                1 => self.fnptr_peer_d1,
                2 => self.fnptr_peer_d2,
                3 => self.fnptr_peer_d3,
                _ => self.fnptr_peer_deep,
            },
        }
    }
}

/// `Feat` paired with its weight at emission time. The wrapper carries the
/// weight value so `Feature::weight()` can return a per-instance value
/// without a global lookup. `Hash` and `PartialEq` ignore the weight so
/// dedup in `FxHashSet<WeightedFeat>` matches `FxHashSet<Feat>` semantics.
#[derive(Clone, Copy)]
struct WeightedFeat {
    feat: Feat,
    weight: u32,
}

impl WeightedFeat {
    fn new(feat: Feat, weights: &WeightConfig) -> Self {
        let weight = weights.weight_for(&feat);
        WeightedFeat { feat, weight }
    }
}

impl PartialEq for WeightedFeat {
    fn eq(&self, other: &Self) -> bool {
        self.feat == other.feat
    }
}
impl Eq for WeightedFeat {}
impl Hash for WeightedFeat {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.feat.hash(state);
    }
}
impl Feature for WeightedFeat {
    fn weight(&self) -> u32 {
        self.weight
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
    synth_map: Option<&FxHashMap<u64, u64>>,
    funcs_by_ep: Option<&FxHashMap<u64, &FunctionAnalysis>>,
    fn_ptrs: Option<&FnPtrIndex>,
    cfg: &FeatureConfig,
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
            for (i, slot) in ops.iter_mut().enumerate().take(insn.op_count() as usize) {
                *slot = Some(insn.op_kind(i as u32));
            }
            let cur = (insn.mnemonic(), ops);
            if cfg.use_bigrams
                && let Some(p) = prev
            {
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
            if depth < cfg.synt_depth
                && let Some(callee_func) = funcs_by_ep.get(&node)
            {
                // Hub gate: don't recurse through high-branching nodes.
                // Same threshold concept as bundling.
                if callee_func.calls.len() > cfg.hub_degree {
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

    // RO-data adjacency features. Both depend on the function-pointer
    // index built once per binary; if it's missing or disabled, skip
    // silently. The ref-count bucket is tier-1 (own-feature, no
    // iteration needed). The peer features are tier-2: like SyntCallee,
    // they only fire once a prior pass has assigned synth IDs to other
    // functions sharing the same vtable layout.
    if cfg.use_fn_ptr
        && let Some(idx) = fn_ptrs
    {
        let sites = idx.sites_of(func.entry_point);
        if !sites.is_empty() {
            // Bucket the reference count. n_sites >= 1, so ilog2 is
            // 0 for one site, 1 for 2-3, 2 for 4-7, etc. — distinct
            // from "no feature emitted" (the not-referenced case).
            feats.insert(Feat::FnPtrRefBucket((sites.len() as u32).ilog2()));

            // Peers — only meaningful with a synth map from a prior
            // pass. Probe ±1..=radius grid neighbors at each site;
            // emit one feature per (offset, synth_id) pair, with
            // FxHashSet collapsing duplicates across F's multiple
            // sites (common for ICF-folded thunks).
            if let Some(map) = synth_map {
                let radius = cfg.fn_ptr_peer_radius as i32;
                for &site_idx in sites {
                    let site = idx.site(site_idx);
                    for delta in 1..=radius {
                        for signed in [-delta, delta] {
                            if let Some(peer) = idx.grid_neighbor(site, signed)
                                && let Some(&s) = map.get(&peer.func)
                            {
                                feats.insert(Feat::FnPtrPeer {
                                    offset: signed as i8,
                                    hash: s,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    feats
}

fn build_graph(
    pe: &PeLoader,
    funcs: &[FunctionAnalysis],
    hasher: &UniversalMinHash,
    synth_map: Option<&FxHashMap<u64, u64>>,
    fn_ptrs: Option<&FnPtrIndex>,
    cfg: &FeatureConfig,
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
                extract_features(pe, f, &iat, synth_map, Some(&funcs_by_ep), fn_ptrs, cfg),
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

    let dirs: &[&FxHashMap<u64, Vec<u64>>] = match cfg.bundle_dir {
        BundleDir::Callees => &[&callees],
        BundleDir::Callers => &[&callers],
        BundleDir::Both => &[&callees, &callers],
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
            if cfg.hops == 0 {
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
                            if let Some(allowed) = cfg.bundle_filter.as_ref()
                                && !allowed.contains(&feat_category(nbr_feat))
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
                if depth >= cfg.hops {
                    continue;
                }
                for adj in dirs {
                    if let Some(neighbors) = adj.get(&node) {
                        // Don't expand THROUGH a hub. We still consumed its
                        // own features when we popped it above.
                        if node != start && neighbors.len() > cfg.hub_degree {
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
        cfg.hops,
        pct(0.50),
        pct(0.90),
        pct(0.99),
        counts.last().copied().unwrap_or(0)
    );

    // Wrap each Feat in WeightedFeat at the grapnel boundary. Keeps the
    // emission pipeline above (extract_features, bundling) in terms of
    // plain Feat — weights apply only at MinHash signature time.
    let bundled: Vec<(u64, Vec<WeightedFeat>)> = bundled
        .into_iter()
        .map(|(addr, feats)| {
            let weighted: Vec<WeightedFeat> = feats
                .into_iter()
                .map(|f| WeightedFeat::new(f, &cfg.weights))
                .collect();
            (addr, weighted)
        })
        .collect();
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

/// All per-binary state the inspectors need bundled together. Constructed
/// once after analysis; pairs as `a` / `b` in the inspector entry points.
struct BinaryCtx<'a> {
    pe: &'a PeLoader,
    funcs_by_ep: FxHashMap<u64, &'a FunctionAnalysis>,
    iat: HashMap<u64, String>,
    names: &'a HashMap<u64, Vec<String>>,
    /// Synthetic-callee map for this binary. `None` before iter 2 / when
    /// iteration is off.
    synth: Option<&'a FxHashMap<u64, u64>>,
    /// RO-data function-pointer site index. `None` when fn-ptr features
    /// are disabled via `--no-fn-ptr`.
    fn_ptrs: Option<&'a FnPtrIndex>,
    /// Per-feature-category weights, used by inspector reports for
    /// weighted-Jaccard math.
    weights: &'a WeightConfig,
}

impl<'a> BinaryCtx<'a> {
    fn new(
        pe: &'a PeLoader,
        funcs: &'a [FunctionAnalysis],
        names: &'a HashMap<u64, Vec<String>>,
        synth: Option<&'a FxHashMap<u64, u64>>,
        fn_ptrs: Option<&'a FnPtrIndex>,
        weights: &'a WeightConfig,
    ) -> Result<Self> {
        let funcs_by_ep = funcs.iter().map(|f| (f.entry_point, f)).collect();
        let iat = pe.iat()?;
        Ok(Self {
            pe,
            funcs_by_ep,
            iat,
            names,
            synth,
            fn_ptrs,
            weights,
        })
    }

    fn extract(&self, func: &FunctionAnalysis, cfg: &FeatureConfig) -> FxHashSet<Feat> {
        extract_features(
            self.pe,
            func,
            &self.iat,
            self.synth,
            Some(&self.funcs_by_ep),
            self.fn_ptrs,
            cfg,
        )
    }

    fn side<'s>(
        &'s self,
        addr: u64,
        func: &'s FunctionAnalysis,
        feats: &'s FxHashSet<Feat>,
    ) -> Side<'s> {
        Side {
            addr,
            func,
            feats,
            pe: self.pe,
            iat: &self.iat,
            names: self.names,
            synth: self.synth,
            fn_ptrs: self.fn_ptrs,
            weights: self.weights,
        }
    }
}

/// Per-side view of a single matched function pair, used by `report_pair`.
struct Side<'a> {
    addr: u64,
    func: &'a FunctionAnalysis,
    feats: &'a FxHashSet<Feat>,
    pe: &'a PeLoader,
    iat: &'a HashMap<u64, String>,
    names: &'a HashMap<u64, Vec<String>>,
    synth: Option<&'a FxHashMap<u64, u64>>,
    fn_ptrs: Option<&'a FnPtrIndex>,
    weights: &'a WeightConfig,
}

/// Categorize a feature for per-bucket reporting and bundle-filter lookups.
fn feat_category(f: &Feat) -> FeatureCategory {
    match f {
        Feat::Bigram(_) => FeatureCategory::Bigram,
        Feat::Import(_) => FeatureCategory::Import,
        Feat::StringLit(_) => FeatureCategory::String,
        Feat::Const(_) => FeatureCategory::Const,
        Feat::BlockCountBucket(_) => FeatureCategory::BlkCount,
        Feat::CallCountBucket(_) => FeatureCategory::CallCount,
        Feat::Nbr { .. } => FeatureCategory::Nbr,
        Feat::SyntCallee { .. } => FeatureCategory::Synt,
        Feat::FnPtrRefBucket(_) | Feat::FnPtrPeer { .. } => FeatureCategory::FnPtr,
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
            trimmed.to_string()
        } else {
            format!("?{:#x}", call.target)
        };
        out.push(label);
    }
    out
}

fn report_pair(
    name: &str,
    a: &Side,
    b: &Side,
    alg_match: &FxHashMap<u64, u64>,
    alg_match_rev: &FxHashMap<u64, u64>,
) {
    let name_short = if name.len() > 78 {
        format!("{}…", &name[..78])
    } else {
        name.to_string()
    };

    let alg_b = alg_match.get(&a.addr).copied();
    let alg_str = match alg_b {
        None => "<no algorithm match>".to_string(),
        Some(b_addr) if b_addr == b.addr => "<correct>".to_string(),
        Some(b_addr) => {
            let alg_names = b
                .names
                .get(&b_addr)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let trim = if alg_names.len() > 64 {
                format!("{}…", &alg_names[..64])
            } else {
                alg_names
            };
            format!("{:#x} ({})", b_addr, trim)
        }
    };

    println!();
    println!("# {}", name_short);
    println!(
        "#   base   {:#x} ({} bytes, {} blocks, {} calls)",
        a.addr,
        a.func.size,
        a.func.basic_blocks.len(),
        a.func.calls.len()
    );
    println!(
        "#   target {:#x} ({} bytes, {} blocks, {} calls)",
        b.addr,
        b.func.size,
        b.func.basic_blocks.len(),
        b.func.calls.len()
    );
    println!("#   algorithm: base → {}", alg_str);

    // Target's match status — was it claimed by another base addr?
    let target_status = match alg_match_rev.get(&b.addr).copied() {
        None => "<unmatched>".to_string(),
        Some(a_addr) if a_addr == a.addr => "<correct (paired with our base)>".to_string(),
        Some(a_addr) => {
            let claim_name = a
                .names
                .get(&a_addr)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let trim = if claim_name.len() > 64 {
                format!("{}…", &claim_name[..64])
            } else {
                claim_name
            };
            format!("claimed by base {:#x} ({})", a_addr, trim)
        }
    };
    println!("#   target ← {}", target_status);

    // Callee lists side-by-side — directly visualizes inlining differences.
    // Annotate each callee with synth-status: ✓=both sides have synth IDs and
    // they're paired, △=both have IDs but different pairs, ·=at least one
    // side missing synth ID, ⌀=internal call but not in synth maps yet.
    let calls_a = callee_labels(a.func, a.pe, a.iat, a.names);
    let calls_b = callee_labels(b.func, b.pe, b.iat, b.names);
    let synth_marks_a: Vec<String> = a
        .func
        .calls
        .iter()
        .map(|c| match a.synth.and_then(|m| m.get(&c.target).copied()) {
            Some(s) => format!("S={}", s),
            None => "—".to_string(),
        })
        .collect();
    let synth_marks_b: Vec<String> = b
        .func
        .calls
        .iter()
        .map(|c| match b.synth.and_then(|m| m.get(&c.target).copied()) {
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
    let mut cats: std::collections::BTreeMap<FeatureCategory, (FxHashSet<Feat>, FxHashSet<Feat>)> =
        Default::default();
    for f in a.feats {
        cats.entry(feat_category(f)).or_default().0.insert(*f);
    }
    for f in b.feats {
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
            c.label(),
            sa.len(),
            sb.len(),
            inter,
            union,
            jac
        );
    }
    let inter_all = a.feats.intersection(b.feats).count();
    let union_all = a.feats.union(b.feats).count();
    let jac_all = if union_all > 0 {
        inter_all as f64 / union_all as f64
    } else {
        0.0
    };
    println!(
        "#     {:>9}: a={:>5} b={:>5} ∩={:>5} ∪={:>5}  J={:.3}",
        "TOTAL",
        a.feats.len(),
        b.feats.len(),
        inter_all,
        union_all,
        jac_all
    );

    // Weighted Jaccard — what the matcher actually approximates via MinHash.
    // This is what determines whether the pair clears the anchor threshold.
    // Note: this is OWN-only (no bundling); the matcher runs with bundling.
    // If hops>0 in the run, the actual matcher view is even richer than this.
    let w_a: u32 = a.feats.iter().map(|f| a.weights.weight_for(f)).sum();
    let w_b: u32 = b.feats.iter().map(|f| b.weights.weight_for(f)).sum();
    let w_inter: u32 = a
        .feats
        .intersection(b.feats)
        .map(|f| a.weights.weight_for(f))
        .sum();
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
    if let (Some(sa), Some(sb)) = (a.synth, b.synth) {
        let mut a_ids: FxHashSet<u64> = FxHashSet::default();
        let mut b_ids: FxHashSet<u64> = FxHashSet::default();
        for c in &a.func.calls {
            if let Some(&s) = sa.get(&c.target) {
                a_ids.insert(s);
            }
        }
        for c in &b.func.calls {
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

    // Fn-ptr peer signal — vtable-adjacency identity. For each RO-data
    // site of F on each side, peers at signed slot offsets within radius
    // 3 contribute Feat::FnPtrPeer { offset, synth_id }. Shared
    // (offset, synth_id) tuples are the cross-binary anchor: F's
    // immediate neighbor in *its* vtable maps to F''s immediate neighbor
    // in *its* vtable, identified by a synth ID confirmed in a prior pass.
    if let (Some(ia), Some(ib), Some(sa), Some(sb)) = (a.fn_ptrs, b.fn_ptrs, a.synth, b.synth) {
        let sites_a = ia.sites_of(a.addr);
        let sites_b = ib.sites_of(b.addr);
        let peer_set = |idx: &FnPtrIndex,
                        site_idxs: &[u32],
                        smap: &FxHashMap<u64, u64>|
         -> FxHashSet<(i8, u64)> {
            let mut out: FxHashSet<(i8, u64)> = FxHashSet::default();
            for &si in site_idxs {
                let site = idx.site(si);
                for delta in 1i32..=3 {
                    for signed in [-delta, delta] {
                        if let Some(peer) = idx.grid_neighbor(site, signed)
                            && let Some(&s) = smap.get(&peer.func)
                        {
                            out.insert((signed as i8, s));
                        }
                    }
                }
            }
            out
        };
        let peers_a = peer_set(ia, sites_a, sa);
        let peers_b = peer_set(ib, sites_b, sb);
        let shared = peers_a.intersection(&peers_b).count();
        if !sites_a.is_empty() || !sites_b.is_empty() {
            println!(
                "#   fn-ptr signal: sites a={} b={} | peer-synth a={} b={} shared={} (each shared = 1 weight-≤16 anchor)",
                sites_a.len(),
                sites_b.len(),
                peers_a.len(),
                peers_b.len(),
                shared
            );
        }
    }
}

fn inspect_patterns(
    patterns: &[String],
    limit: usize,
    sorted: &[(u64, u64)],
    a: &BinaryCtx,
    b: &BinaryCtx,
    cfg: &FeatureConfig,
) -> Result<()> {
    let mut by_name_a: FxHashMap<&str, Vec<u64>> = FxHashMap::default();
    for (addr, ns) in a.names {
        for s in ns {
            by_name_a.entry(s.as_str()).or_default().push(*addr);
        }
    }
    let mut by_name_b: FxHashMap<&str, Vec<u64>> = FxHashMap::default();
    for (addr, ns) in b.names {
        for s in ns {
            by_name_b.entry(s.as_str()).or_default().push(*addr);
        }
    }
    let alg_match: FxHashMap<u64, u64> = sorted.iter().copied().collect();
    let alg_match_rev: FxHashMap<u64, u64> = sorted.iter().map(|&(x, y)| (y, x)).collect();

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
            let (Some(&fa), Some(&fb)) = (a.funcs_by_ep.get(&addr_a), b.funcs_by_ep.get(&addr_b))
            else {
                continue;
            };
            let feats_a = a.extract(fa, cfg);
            let feats_b = b.extract(fb, cfg);
            report_pair(
                name,
                &a.side(addr_a, fa, &feats_a),
                &b.side(addr_b, fb, &feats_b),
                &alg_match,
                &alg_match_rev,
            );
        }
    }
    Ok(())
}

fn inspect_samples(
    n: usize,
    sorted: &[(u64, u64)],
    names_in_a: &FxHashSet<&str>,
    names_in_b: &FxHashSet<&str>,
    a: &BinaryCtx,
    b: &BinaryCtx,
    cfg: &FeatureConfig,
) -> Result<()> {
    // Build name → addrs maps.
    let mut by_name_a: FxHashMap<&str, Vec<u64>> = FxHashMap::default();
    for (addr, ns) in a.names {
        for s in ns {
            by_name_a.entry(s.as_str()).or_default().push(*addr);
        }
    }
    let mut by_name_b: FxHashMap<&str, Vec<u64>> = FxHashMap::default();
    for (addr, ns) in b.names {
        for s in ns {
            by_name_b.entry(s.as_str()).or_default().push(*addr);
        }
    }

    let alg_match: FxHashMap<u64, u64> = sorted.iter().copied().collect();
    let alg_match_rev: FxHashMap<u64, u64> = sorted.iter().map(|&(x, y)| (y, x)).collect();

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
        if !a.funcs_by_ep.contains_key(&addr_a) || !b.funcs_by_ep.contains_key(&addr_b) {
            continue;
        }
        if alg_match.get(&addr_a).copied() == Some(addr_b) {
            tp_pool.push((name, addr_a, addr_b));
        } else {
            fn_pool.push((name, addr_a, addr_b));
        }
    }

    // Stable sort to get deterministic samples across runs.
    tp_pool.sort_by_key(|&(_, addr, _)| addr);
    fn_pool.sort_by_key(|&(_, addr, _)| addr);

    let stride_pick = |pool: &[(&str, u64, u64)], k: usize| -> Vec<(String, u64, u64)> {
        if pool.is_empty() || k == 0 {
            return Vec::new();
        }
        let k = k.min(pool.len());
        let stride = pool.len() / k;
        (0..k)
            .map(|i| {
                let (s, x, y) = pool[i * stride];
                (s.to_string(), x, y)
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
            let fa = a.funcs_by_ep[addr_a];
            let fb = b.funcs_by_ep[addr_b];
            let feats_a = a.extract(fa, cfg);
            let feats_b = b.extract(fb, cfg);
            report_pair(
                name,
                &a.side(*addr_a, fa, &feats_a),
                &b.side(*addr_b, fb, &feats_b),
                &alg_match,
                &alg_match_rev,
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
}

#[allow(clippy::too_many_arguments)]
fn run_match(
    args: &Args,
    pe1: &PeLoader,
    funcs1: &[FunctionAnalysis],
    pe2: &PeLoader,
    funcs2: &[FunctionAnalysis],
    fn_ptrs1: Option<&FnPtrIndex>,
    fn_ptrs2: Option<&FnPtrIndex>,
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
        size_mismatch_ratio: args.size_mismatch_ratio,
        pre_match_on_identifiers: false,
        min_band_collisions: args.min_band_collisions,
        asymmetric_hub_gate: args.asymmetric_hub_gate,
    };
    let hasher = config.hasher(args.seed);
    let feat_cfg = FeatureConfig::from_args(args);

    // Canonical pair state: base_addr -> (target_addr, sim, synth_id).
    // `synth_a`/`synth_b` are derived per pass from this map. With
    // `--allow-revision`, pass N can overwrite an existing pair (a, b_old)
    // with (a, b_new) if the new similarity beats the old by
    // `--revise-margin`. Without that flag, the original lock-existing-pairs
    // rule applies: first pass to confirm wins, no overwrites.
    let mut confirmed: FxHashMap<u64, (u64, f64, u64)> = FxHashMap::default();
    let mut target_to_base: FxHashMap<u64, u64> = FxHashMap::default();
    let mut next_synth_id: u64 = 0;

    let mut last_precision = 0.0;
    let mut last_recall = 0.0;
    let mut last_valid = 0usize;
    let mut last_tp = 0usize;

    let total_passes = args.iterations.max(1);
    for pass in 0..total_passes {
        // Derive per-pass synth maps from the canonical confirmed state.
        // Recomputed each pass so revisions immediately propagate.
        let synth_a: FxHashMap<u64, u64> =
            confirmed.iter().map(|(&a, &(_, _, s))| (a, s)).collect();
        let synth_b: FxHashMap<u64, u64> = confirmed.values().map(|&(b, _, s)| (b, s)).collect();
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
                if feat_cfg.use_bigrams { "on" } else { "off" },
                feat_cfg.hops,
                feat_cfg.bundle_filter,
                synth_a.len(),
            );
        }
        let g1 = build_graph(pe1, funcs1, &hasher, synth_a_ref, fn_ptrs1, &feat_cfg)?;
        let g2 = build_graph(pe2, funcs2, &hasher, synth_b_ref, fn_ptrs2, &feat_cfg)?;

        if !quiet {
            eprintln!("pass {}/{}: matching", pass + 1, total_passes);
        }
        let (new_matches, mstats) = config.run_traced(&g1, &g2);
        if !quiet {
            eprintln!(
                "  pass {} stats: lsh_cands={} above_anchor={} | p3 confirmed={} skip_a={} skip_b={} | p4 propose={} hub={} size={} below_thr={} skip_a={} skip_b={} confirmed={}",
                pass + 1,
                mstats.phase2_lsh_candidates,
                mstats.phase2_above_anchor,
                mstats.phase3_confirmed,
                mstats.phase3_skip_a_taken,
                mstats.phase3_skip_b_taken,
                mstats.phase4_propose,
                mstats.phase4_blocked_hub,
                mstats.phase4_blocked_size,
                mstats.phase4_below_threshold,
                mstats.phase4_skip_a_taken,
                mstats.phase4_skip_b_taken,
                mstats.phase4_confirmed,
            );
        }

        // Apply pairs to the canonical state. Without --allow-revision, this
        // is the original lock rule (skip if either side already paired).
        // With --allow-revision, a new pair can overwrite an existing one if
        // its similarity beats both (a's old pair, if any) and (b's old pair,
        // if any) by at least --revise-margin.
        let mut new_count = 0usize;
        let mut revised_count = 0usize;
        let mut blocked_count = 0usize;
        for (&a, &(b, sim)) in &new_matches {
            let old_a_pair = confirmed.get(&a).copied();
            let old_b_base = target_to_base.get(&b).copied();
            let old_b_pair = old_b_base.and_then(|oa| confirmed.get(&oa).copied());

            let win_a = match old_a_pair {
                None => true,
                Some((_, old_sim, _)) => !args.no_revision && sim > old_sim + args.revise_margin,
            };
            let win_b = match old_b_pair {
                None => true,
                Some((_, old_sim, _)) => !args.no_revision && sim > old_sim + args.revise_margin,
            };
            if !win_a || !win_b {
                blocked_count += 1;
                continue;
            }

            let is_revision = old_a_pair.is_some() || old_b_pair.is_some();
            // Revoke conflicting old pairs so the bipartite invariant holds.
            if let Some((old_b, _, _)) = old_a_pair {
                target_to_base.remove(&old_b);
            }
            if let Some(oa) = old_b_base {
                confirmed.remove(&oa);
            }
            let s = next_synth_id;
            next_synth_id += 1;
            confirmed.insert(a, (b, sim, s));
            target_to_base.insert(b, a);
            if is_revision {
                revised_count += 1;
            } else {
                new_count += 1;
            }
        }
        if !quiet {
            eprintln!(
                "  pass {}: {} matches this pass, {} new, {} revised, {} blocked (canonical: {})",
                pass + 1,
                new_matches.len(),
                new_count,
                revised_count,
                blocked_count,
                confirmed.len()
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
            // Per-pass stats over `new_matches` show the trajectory of what
            // each individual pass found (with its current synth context).
            let mut pass_named = 0usize;
            let mut pass_tp = 0usize;
            for (a, (b, _)) in &new_matches {
                if let (Some(sa), Some(sb)) = (sets_a.get(a), sets_b.get(b)) {
                    if sa.is_empty() || sb.is_empty() {
                        continue;
                    }
                    pass_named += 1;
                    if sa.iter().any(|n| sb.contains(n)) {
                        pass_tp += 1;
                    }
                }
            }
            let pass_prec = pass_tp as f64 / pass_named.max(1) as f64;
            let pass_rec = pass_tp as f64 / pdb.baseline_addrs.max(1) as f64;

            // Canonical (confirmed) stats are the actual final output.
            let mut cum_named = 0usize;
            let mut cum_tp = 0usize;
            for (a, (b, _, _)) in &confirmed {
                if let (Some(sa), Some(sb)) = (sets_a.get(a), sets_b.get(b)) {
                    if sa.is_empty() || sb.is_empty() {
                        continue;
                    }
                    cum_named += 1;
                    if sa.iter().any(|n| sb.contains(n)) {
                        cum_tp += 1;
                    }
                }
            }
            let cum_prec = cum_tp as f64 / cum_named.max(1) as f64;
            let cum_rec = cum_tp as f64 / pdb.baseline_addrs.max(1) as f64;
            if !quiet {
                println!(
                    "# pass {}/{}: this-pass matched={} prec={:.2}% recall={:.2}% | canonical matched={} prec={:.2}% recall={:.2}%",
                    pass + 1,
                    total_passes,
                    new_matches.len(),
                    pass_prec * 100.0,
                    pass_rec * 100.0,
                    confirmed.len(),
                    cum_prec * 100.0,
                    cum_rec * 100.0,
                );
            }
            // Final reported metrics are the canonical (confirmed) values,
            // not last-pass — this is the actual matcher output.
            last_precision = cum_prec;
            last_recall = cum_rec;
            last_valid = cum_named;
            last_tp = cum_tp;
        }
    }

    let mut sorted: Vec<(u64, u64)> = confirmed.iter().map(|(&a, &(b, _, _))| (a, b)).collect();
    sorted.sort_unstable();

    let time_secs = start.elapsed().as_secs_f64();

    // Derive final synth maps from canonical state for downstream
    // inspectors and cache export.
    let synth_a: FxHashMap<u64, u64> = confirmed.iter().map(|(&a, &(_, _, s))| (a, s)).collect();
    let synth_b: FxHashMap<u64, u64> = confirmed.values().map(|&(b, _, s)| (b, s)).collect();
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
    })
}

/// Weighted Jaccard between two feature sets, scored under the given
/// `WeightConfig`. Used by the achievability-analysis path.
fn weighted_jaccard(a: &FxHashSet<Feat>, b: &FxHashSet<Feat>, w: &WeightConfig) -> f64 {
    let inter_w: u32 = a.intersection(b).map(|f| w.weight_for(f)).sum();
    let union_w: u32 = a.union(b).map(|f| w.weight_for(f)).sum();
    if union_w == 0 {
        0.0
    } else {
        inter_w as f64 / union_w as f64
    }
}

/// Achievability analysis: for every PDB ground-truth pair, compute the
/// weighted Jaccard of feature sets (using the final synth maps from the
/// matcher run) and cross-tab against the algorithm's outcome.
///
/// Tells you the structural ceiling: how many ground-truth pairs are
/// reachable by anchor mode at the current `--anchor` threshold, vs how
/// many require Phase 4 propagation, vs how many are below all thresholds
/// and effectively impossible.
#[allow(clippy::too_many_arguments)]
fn measure_achievability(
    pe1: &PeLoader,
    funcs1: &[FunctionAnalysis],
    pe2: &PeLoader,
    funcs2: &[FunctionAnalysis],
    fn_ptrs1: Option<&FnPtrIndex>,
    fn_ptrs2: Option<&FnPtrIndex>,
    pdb: &PdbContext,
    result: &RunResult,
    feat_cfg: &FeatureConfig,
    anchor_threshold: f64,
    propagate_threshold: f64,
) -> Result<()> {
    use rayon::prelude::*;

    eprintln!("achievability: extracting features for all functions...");
    let iat_a = pe1.iat()?;
    let iat_b = pe2.iat()?;
    let funcs1_by_ep: FxHashMap<u64, &FunctionAnalysis> =
        funcs1.iter().map(|f| (f.entry_point, f)).collect();
    let funcs2_by_ep: FxHashMap<u64, &FunctionAnalysis> =
        funcs2.iter().map(|f| (f.entry_point, f)).collect();

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

    let feats_a: FxHashMap<u64, FxHashSet<Feat>> = funcs1
        .par_iter()
        .map(|f| {
            (
                f.entry_point,
                extract_features(
                    pe1,
                    f,
                    &iat_a,
                    synth_a_ref,
                    Some(&funcs1_by_ep),
                    fn_ptrs1,
                    feat_cfg,
                ),
            )
        })
        .collect();
    let feats_b: FxHashMap<u64, FxHashSet<Feat>> = funcs2
        .par_iter()
        .map(|f| {
            (
                f.entry_point,
                extract_features(
                    pe2,
                    f,
                    &iat_b,
                    synth_b_ref,
                    Some(&funcs2_by_ep),
                    fn_ptrs2,
                    feat_cfg,
                ),
            )
        })
        .collect();

    // PDB name → first canonical address per side.
    let mut by_name_a: FxHashMap<&str, u64> = FxHashMap::default();
    for (addr, ns) in &pdb.names_a {
        for n in ns {
            by_name_a.entry(n.as_str()).or_insert(*addr);
        }
    }
    let mut by_name_b: FxHashMap<&str, u64> = FxHashMap::default();
    for (addr, ns) in &pdb.names_b {
        for n in ns {
            by_name_b.entry(n.as_str()).or_insert(*addr);
        }
    }

    // Algorithm result + per-address name set lookups (for outcome check).
    let alg_match: FxHashMap<u64, u64> = result.sorted.iter().copied().collect();
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

    // Iterate ground-truth pairs (one canonical (a, b) per shared PDB name).
    // We use base_addr as the dedup key so a multi-aliased base function
    // contributes one pair per base address, not per name. Pairs that
    // resolve to the same base address are deduped — only the first wins.
    let mut seen_a: FxHashSet<u64> = FxHashSet::default();
    let mut bucket_total = [0usize; 10];
    let mut bucket_correct = [0usize; 10];
    let mut bucket_wrong = [0usize; 10];
    let mut bucket_missed = [0usize; 10];
    let mut total_pairs = 0usize;

    for (name, &addr_a) in &by_name_a {
        let Some(&addr_b) = by_name_b.get(name) else {
            continue;
        };
        if !seen_a.insert(addr_a) {
            continue;
        }
        let Some(fa) = feats_a.get(&addr_a) else {
            continue;
        };
        let Some(fb) = feats_b.get(&addr_b) else {
            continue;
        };

        let j = weighted_jaccard(fa, fb, &feat_cfg.weights);
        let bucket = ((j * 10.0) as usize).min(9);
        total_pairs += 1;
        bucket_total[bucket] += 1;

        // Outcome: did algorithm match (addr_a, ?), and is ? a name-overlap
        // with addr_a's PDB names?
        match alg_match.get(&addr_a) {
            None => bucket_missed[bucket] += 1,
            Some(&alg_b) => {
                let correct = match (sets_a.get(&addr_a), sets_b.get(&alg_b)) {
                    (Some(sa), Some(sb)) => sa.iter().any(|n: &&str| sb.contains(n)),
                    _ => false,
                };
                if correct {
                    bucket_correct[bucket] += 1;
                } else {
                    bucket_wrong[bucket] += 1;
                }
            }
        }
    }

    // ----- print -----
    println!("# ============== achievability analysis ==============");
    println!(
        "# {} ground-truth pairs (PDB name in both binaries, both addrs analyzed)",
        total_pairs
    );
    println!("#");
    println!("# weighted Jaccard distribution (with FINAL synth maps applied):");
    println!(
        "# {:<14} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "J range", "total", "correct", "wrong", "missed", "alg-rec%"
    );
    for i in (0..10).rev() {
        let lo = i as f64 / 10.0;
        let hi = (i + 1) as f64 / 10.0;
        let total = bucket_total[i];
        let correct = bucket_correct[i];
        let wrong = bucket_wrong[i];
        let missed = bucket_missed[i];
        let rec = if total > 0 {
            correct as f64 / total as f64 * 100.0
        } else {
            0.0
        };
        // Mark which buckets are below thresholds.
        let marker = if (lo + 1e-9) >= anchor_threshold {
            " (anchor-eligible)"
        } else if (lo + 1e-9) >= propagate_threshold {
            " (propagate-only)"
        } else {
            " (sub-threshold)"
        };
        println!(
            "# [{:.2}, {:.2}) {:>8} {:>8} {:>8} {:>8} {:>7.1}%{}",
            lo, hi, total, correct, wrong, missed, rec, marker
        );
    }

    println!("#");
    println!("# Cumulative (ground-truth pairs WITH J >= threshold AND algorithm outcome):");
    println!(
        "# {:>10} {:>10} {:>10} {:>10}   {:>10} {:>10} {:>10}",
        "J>=", "GT_pairs", "%_of_GT", "ceiling%", "alg_match", "alg_correct", "alg_recall%"
    );
    let mut cum_total = 0usize;
    let mut cum_correct = 0usize;
    let mut cum_wrong = 0usize;
    let mut cum_missed = 0usize;
    for i in (0..10).rev() {
        cum_total += bucket_total[i];
        cum_correct += bucket_correct[i];
        cum_wrong += bucket_wrong[i];
        cum_missed += bucket_missed[i];
        let lo = i as f64 / 10.0;
        let frac_gt = cum_total as f64 / total_pairs.max(1) as f64 * 100.0;
        let ceiling = cum_total as f64 / pdb.baseline_addrs.max(1) as f64 * 100.0;
        let alg_matched = cum_correct + cum_wrong;
        let alg_rec_within = if cum_total > 0 {
            cum_correct as f64 / cum_total as f64 * 100.0
        } else {
            0.0
        };
        let _ = cum_missed;
        println!(
            "# {:>9.2}  {:>10} {:>9.1}% {:>9.1}%   {:>10} {:>10} {:>10.1}%",
            lo, cum_total, frac_gt, ceiling, alg_matched, cum_correct, alg_rec_within
        );
    }
    println!("#");
    println!("# Interpretation:");
    println!("#   - 'ceiling%' = fraction of total recall ceiling (pairs with PDB names");
    println!("#     in both binaries) reachable IF every ground-truth pair with J >= the");
    println!("#     threshold were correctly matched by the algorithm.");
    println!("#   - 'alg_recall%' = of THOSE pairs (J >= threshold), what fraction did");
    println!("#     the algorithm get correct? Should approach 100% as threshold rises.");
    println!(
        "#   - Current --anchor={:.2} --propagate={:.2}: pairs below propagate are",
        anchor_threshold, propagate_threshold
    );
    println!("#     structurally impossible; pairs in [propagate, anchor) need Phase 4.");
    Ok(())
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

#[allow(clippy::too_many_arguments)]
fn run_sweep(
    base_args: &Args,
    pe1: &PeLoader,
    funcs1: &[FunctionAnalysis],
    pe2: &PeLoader,
    funcs2: &[FunctionAnalysis],
    fn_ptrs1: Option<&FnPtrIndex>,
    fn_ptrs2: Option<&FnPtrIndex>,
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
                    Box::new(|a: &mut Args| a.bundle = BundleDir::Callees),
                ),
                (
                    "bundle=callers",
                    Box::new(|a: &mut Args| a.bundle = BundleDir::Callers),
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
                        a.bundle_features =
                            Some(vec![FeatureCategory::Import, FeatureCategory::String])
                    }),
                ),
                (
                    "string only",
                    Box::new(|a: &mut Args| {
                        a.bundle_features = Some(vec![FeatureCategory::String])
                    }),
                ),
                (
                    "import,string,const,callcount,blkcount",
                    Box::new(|a: &mut Args| {
                        a.bundle_features = Some(vec![
                            FeatureCategory::Import,
                            FeatureCategory::String,
                            FeatureCategory::Const,
                            FeatureCategory::CallCount,
                            FeatureCategory::BlkCount,
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
    let baseline = run_match(
        base_args,
        pe1,
        funcs1,
        pe2,
        funcs2,
        fn_ptrs1,
        fn_ptrs2,
        Some(pdb),
        true,
    )?;
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
            "# {:<42} {:>7} {:>7} {:>9} {:>8} {:>7}   Δ vs baseline",
            "config", "prec", "recall", "matched", "valid", "time"
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
            let r = match run_match(
                &a,
                pe1,
                funcs1,
                pe2,
                funcs2,
                fn_ptrs1,
                fn_ptrs2,
                Some(pdb),
                true,
            ) {
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

#[allow(clippy::too_many_arguments)]
fn run_sweep_combos(
    base_args: &Args,
    pe1: &PeLoader,
    funcs1: &[FunctionAnalysis],
    pe2: &PeLoader,
    funcs2: &[FunctionAnalysis],
    fn_ptrs1: Option<&FnPtrIndex>,
    fn_ptrs2: Option<&FnPtrIndex>,
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
    let all_bundle = || {
        Some(vec![
            FeatureCategory::Import,
            FeatureCategory::String,
            FeatureCategory::Const,
            FeatureCategory::CallCount,
            FeatureCategory::BlkCount,
        ])
    };
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
            Box::new(move |a: &mut Args| {
                a.bands = 50;
                a.min_features = 32;
                a.max_degree = 32;
                a.bundle_features = all_bundle();
            }),
        ),
        (
            "min-features=32 + bundle+callcount,blkcount",
            Box::new(move |a: &mut Args| {
                a.min_features = 32;
                a.bundle_features = all_bundle();
            }),
        ),
        (
            "bundle+callcount,blkcount + max-degree=128",
            Box::new(move |a: &mut Args| {
                a.bundle_features = all_bundle();
                a.max_degree = 128;
            }),
        ),
        (
            "max-recall push: bands=200 + bundle+callcount,blkcount",
            Box::new(move |a: &mut Args| {
                a.bands = 200;
                a.bundle_features = all_bundle();
            }),
        ),
        (
            "max-recall push: --no-bigrams + bundle+callcount,blkcount",
            Box::new(move |a: &mut Args| {
                a.no_bigrams = true;
                a.bundle_features = all_bundle();
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
    let baseline = run_match(
        base_args,
        pe1,
        funcs1,
        pe2,
        funcs2,
        fn_ptrs1,
        fn_ptrs2,
        Some(pdb),
        true,
    )?;
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
        "# {:<58} {:>7} {:>7} {:>9} {:>8} {:>7}   Δ vs baseline",
        "config", "prec", "recall", "matched", "valid", "time"
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
        let r = match run_match(
            &a,
            pe1,
            funcs1,
            pe2,
            funcs2,
            fn_ptrs1,
            fn_ptrs2,
            Some(pdb),
            true,
        ) {
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

    // Build the RO-data function-pointer index once per binary. Cheap
    // (<1ms on typical binaries) and reused across every match pass and
    // every sweep run. The `--no-fn-ptr` ablation gates emission via
    // FeatureConfig.use_fn_ptr, not via skipping the build — keeping the
    // index always-available simplifies plumbing for sweep variants that
    // might toggle the flag.
    let entries1: FxHashSet<u64> = funcs1.iter().map(|f| f.entry_point).collect();
    let entries2: FxHashSet<u64> = funcs2.iter().map(|f| f.entry_point).collect();
    let fn_ptrs1 = find_fn_ptr_sites(&pe1, &entries1)?;
    let fn_ptrs2 = find_fn_ptr_sites(&pe2, &entries2)?;
    tick(&format!(
        "  fn-ptr sites: base={} ({} funcs) target={} ({} funcs)",
        fn_ptrs1.len(),
        fn_ptrs1.distinct_funcs(),
        fn_ptrs2.len(),
        fn_ptrs2.distinct_funcs(),
    ));
    let fn_ptrs1 = Some(&fn_ptrs1);
    let fn_ptrs2 = Some(&fn_ptrs2);

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
            fn_ptrs1,
            fn_ptrs2,
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
            fn_ptrs1,
            fn_ptrs2,
            pdb_ctx.as_ref().expect("sweep-combos requires PDBs"),
        );
    }

    let result = run_match(
        &args,
        &pe1,
        &funcs1,
        &pe2,
        &funcs2,
        fn_ptrs1,
        fn_ptrs2,
        pdb_ctx.as_ref(),
        false,
    )?;
    tick("matching done");

    if let Some(path) = &args.emit_matches {
        write_matches_cache(path, &args, &result)?;
        tick(&format!("wrote matches cache to {}", path.display()));
    }

    if let Some(path) = &args.generate_pdb {
        // Refuse to clobber a real PDB — but allow overwriting one we generated
        // ourselves (detected via the EnvBlock canary baked in by pdb_writer).
        if path.exists() && !pdb_analyzer::should_replace(path).unwrap_or(false) {
            anyhow::bail!(
                "refusing to overwrite existing PDB at {} (not generated by binfold)",
                path.display()
            );
        }

        // Reuse names_a from the validation PDB context if available, otherwise
        // load the base PDB just for symbol names.
        let names_a_owned;
        let names_a: &HashMap<u64, Vec<String>> = if let Some(ctx) = &pdb_ctx {
            &ctx.names_a
        } else {
            names_a_owned = load_pdb_names(&args.base, &pe1)?;
            &names_a_owned
        };

        let sizes_b: FxHashMap<u64, usize> =
            funcs2.iter().map(|f| (f.entry_point, f.size)).collect();

        let mut pdb_functions: Vec<pdb_writer::FunctionInfo> = Vec::new();
        let mut missing_names = 0usize;
        let mut missing_sizes = 0usize;
        for &(base_addr, target_addr) in &result.sorted {
            let Some(name) = names_a.get(&base_addr).and_then(|v| v.first()) else {
                missing_names += 1;
                continue;
            };
            let Some(&size) = sizes_b.get(&target_addr) else {
                missing_sizes += 1;
                continue;
            };
            pdb_functions.push(pdb_writer::FunctionInfo {
                address: target_addr,
                size: size as u32,
                name: name.clone(),
            });
        }

        let pdb_info = extract_pdb_info(&pe2)?;
        pdb_writer::generate_pdb(&pe2, &pdb_info, &pdb_functions, path)?;
        tick(&format!(
            "wrote PDB to {} ({} named, {} matches lacked base names, {} matches lacked target sizes)",
            path.display(),
            pdb_functions.len(),
            missing_names,
            missing_sizes,
        ));
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
        let feat_cfg = FeatureConfig::from_args(&args);
        let ctx_a = BinaryCtx::new(
            &pe1,
            &funcs1,
            &pdb.names_a,
            synth_a_ref,
            fn_ptrs1,
            &feat_cfg.weights,
        )?;
        let ctx_b = BinaryCtx::new(
            &pe2,
            &funcs2,
            &pdb.names_b,
            synth_b_ref,
            fn_ptrs2,
            &feat_cfg.weights,
        )?;
        if args.measure_achievability {
            measure_achievability(
                &pe1,
                &funcs1,
                &pe2,
                &funcs2,
                fn_ptrs1,
                fn_ptrs2,
                pdb,
                &result,
                &feat_cfg,
                args.anchor,
                args.propagate,
            )?;
        }
        if args.inspect_samples > 0 {
            inspect_samples(
                args.inspect_samples,
                &result.sorted,
                &names_in_a,
                &names_in_b,
                &ctx_a,
                &ctx_b,
                &feat_cfg,
            )?;
        }

        if !args.inspect_patterns.is_empty() {
            inspect_patterns(
                &args.inspect_patterns,
                args.inspect_pattern_limit,
                &result.sorted,
                &ctx_a,
                &ctx_b,
                &feat_cfg,
            )?;
        }
    }

    Ok(())
}
