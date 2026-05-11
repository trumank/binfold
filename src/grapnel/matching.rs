use std::collections::VecDeque;
use std::hash::Hash;
use std::ops::AddAssign;

use rayon::prelude::*;
use rustc_hash::{FxBuildHasher, FxHashMap, FxHashSet};

use super::UniversalMinHash;
use super::graph::Graph;
use super::lsh::LshIndex;

/// Configuration parameters for the graph matching algorithm.
#[derive(Debug, Clone)]
pub struct MatcherConfig {
    /// Total number of hash permutations per node.
    pub k_permutations: usize,
    /// Number of bands for LSH candidate generation.
    pub lsh_bands: usize,
    /// Minimum feature count to index a node in LSH.
    pub min_features_for_lsh: u32,
    /// Minimum Jaccard similarity for initial LSH anchor matches.
    pub anchor_threshold: f64,
    /// Minimum Jaccard similarity for topological graph propagation.
    pub propagation_threshold: f64,
    /// Maximum neighbor count to process during graph propagation.
    pub max_propagation_degree: usize,
    /// Maximum allowed size ratio between candidate nodes during propagation.
    pub size_mismatch_ratio: f32,
    /// Phase 4 hub-gate semantics. `false` (default): skip propagation when
    /// EITHER side's edge list exceeds `max_propagation_degree`. `true`:
    /// skip only when BOTH sides exceed (i.e., when the SMALLER side is
    /// also a hub). The asymmetric variant accepts paths where one side is
    /// a hub due to inlining asymmetry but the other isn't — which is
    /// exactly the cross-compiler case where target inlines more than base
    /// (or vice versa). Propagation cost scales with the larger side, so
    /// asymmetric mode can be significantly slower on hub-heavy graphs.
    pub asymmetric_hub_gate: bool,
}

/// Phase 2 (LSH retrieval + anchor filter) counters.
#[derive(Default, Debug, Clone)]
pub struct Phase2Stats {
    /// Total candidates returned by LSH across all Phase 2 queries (sum of
    /// per-query buf sizes after dedup). Includes pairs that won't pass
    /// `anchor_threshold`.
    pub lsh_candidates: usize,
    /// Candidates that survived the `anchor_threshold` filter and entered
    /// Phase 3.
    pub above_anchor: usize,
}

/// Phase 3 (greedy anchor resolution) counters.
#[derive(Default, Debug, Clone)]
pub struct Phase3Stats {
    /// Candidates that became confirmed pairs (won greedy resolution).
    pub confirmed: usize,
    /// Candidates skipped because their `node1` was already matched.
    pub skip_a_taken: usize,
    /// Candidates skipped because their `node2` was already matched.
    pub skip_b_taken: usize,
}

/// Phase 4 (graph propagation) counters.
#[derive(Default, Debug, Clone)]
pub struct Phase4Stats {
    /// Total `propagate(...)` invocations (one per dependency-or-dependent
    /// edge from each confirmed pair).
    pub propose: usize,
    /// Invocations rejected by the hub gate.
    pub blocked_hub: usize,
    /// Candidate pairs filtered by `size_mismatch_ratio`.
    pub blocked_size: usize,
    /// Candidate pairs whose Jaccard fell below `propagation_threshold`.
    pub below_threshold: usize,
    /// Candidate pairs skipped because base was already matched.
    pub skip_a_taken: usize,
    /// Candidate pairs skipped because target was already matched.
    pub skip_b_taken: usize,
    /// Pairs that became confirmed via propagation.
    pub confirmed: usize,
}

/// A confirmed pair from the matching pipeline.
///
/// `similarity` is the Jaccard score (intersection / `k_permutations`) at
/// the time the pair was confirmed — callers doing confidence-weighted
/// reasoning across iterations should read it from here rather than
/// recomputing.
#[derive(Debug, Clone)]
pub struct Match<Id> {
    pub target: Id,
    pub similarity: f64,
}

/// Per-pass match statistics — counts at each filter point so callers can
/// see WHERE pairs are being lost (LSH retrieval, anchor threshold, greedy
/// lock-out, propagation gates). Grouped by phase; sum across passes with
/// `+=`.
#[derive(Default, Debug, Clone)]
pub struct MatchStats {
    pub phase2: Phase2Stats,
    pub phase3: Phase3Stats,
    pub phase4: Phase4Stats,
}

impl AddAssign<&Phase2Stats> for Phase2Stats {
    fn add_assign(&mut self, rhs: &Self) {
        self.lsh_candidates += rhs.lsh_candidates;
        self.above_anchor += rhs.above_anchor;
    }
}

impl AddAssign<&Phase3Stats> for Phase3Stats {
    fn add_assign(&mut self, rhs: &Self) {
        self.confirmed += rhs.confirmed;
        self.skip_a_taken += rhs.skip_a_taken;
        self.skip_b_taken += rhs.skip_b_taken;
    }
}

impl AddAssign<&Phase4Stats> for Phase4Stats {
    fn add_assign(&mut self, rhs: &Self) {
        self.propose += rhs.propose;
        self.blocked_hub += rhs.blocked_hub;
        self.blocked_size += rhs.blocked_size;
        self.below_threshold += rhs.below_threshold;
        self.skip_a_taken += rhs.skip_a_taken;
        self.skip_b_taken += rhs.skip_b_taken;
        self.confirmed += rhs.confirmed;
    }
}

impl AddAssign<&MatchStats> for MatchStats {
    fn add_assign(&mut self, rhs: &Self) {
        self.phase2 += &rhs.phase2;
        self.phase3 += &rhs.phase3;
        self.phase4 += &rhs.phase4;
    }
}

impl MatcherConfig {
    /// Creates a new `UniversalMinHash` instance configured with the current parameters.
    pub fn hasher(&self, seed: u64) -> UniversalMinHash {
        UniversalMinHash::new(seed, self.k_permutations)
    }

    /// Executes the graph matching pipeline with the current configuration.
    ///
    /// Returns `(matches, stats)`. Callers that don't care about the
    /// per-phase counters can discard them with `let (m, _) = ...`.
    #[inline]
    pub fn run<Id>(
        &self,
        graph1: &Graph<Id>,
        graph2: &Graph<Id>,
    ) -> (FxHashMap<Id, Match<Id>>, MatchStats)
    where
        Id: Clone + Eq + Ord + Hash + Send + Sync,
    {
        match_graphs(graph1, graph2, self)
    }
}

/// Executes the graph matching pipeline between two graphs.
///
/// Matches are found via LSH indexing, querying, greedy anchor resolution,
/// and graph propagation.
///
/// # Arguments
/// * `graph1` - Base graph.
/// * `graph2` - Target graph.
/// * `config` - Algorithm configuration.
///
/// # Returns
/// `(matches, stats)`. `matches` maps `graph1` node identifiers to a
/// [`Match`] giving the paired `graph2` id and the Jaccard similarity at
/// the time the pair was confirmed. `stats` reports per-phase counters
/// describing where candidate pairs were lost (LSH retrieval / anchor /
/// greedy / hub / size / threshold). Callers that don't care about the
/// counters can discard them with `let (matches, _) = match_graphs(...)`.
pub fn match_graphs<Id>(
    graph1: &Graph<Id>,
    graph2: &Graph<Id>,
    config: &MatcherConfig,
) -> (FxHashMap<Id, Match<Id>>, MatchStats)
where
    Id: Clone + Eq + Ord + Hash + Send + Sync,
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut stats = MatchStats::default();
    let est = graph1.nodes.len();
    let mut final_matches: FxHashMap<Id, Match<Id>> =
        FxHashMap::with_capacity_and_hasher(est, FxBuildHasher);
    let mut matched_graph2 = FxHashSet::with_capacity_and_hasher(est, FxBuildHasher);

    // --- PHASE 1: Build LSH for Graph 2 ---
    let lsh = LshIndex::new(
        graph2.nodes.iter().filter_map(|(node_id, node)| {
            if node.total_weight >= config.min_features_for_lsh {
                Some((node_id, node.signature.as_slice()))
            } else {
                None
            }
        }),
        config.lsh_bands,
    );

    // --- PHASE 2: Query LSH & Calculate Exact Similarity ---
    // Parallelized over graph1.nodes — every iteration is read-only on
    // graph1, graph2, and lsh, so we can fan out across all cores. Each
    // worker thread keeps its own `query_buf` to avoid allocator churn.
    //
    // We sort by similarity DESC but use Id as a secondary key so the
    // Phase 3 greedy resolver is deterministic — ties at sim=1.0 (structural
    // twins) get resolved consistently across runs instead of in
    // par_iter-collection order.
    let phase2_total = AtomicUsize::new(0);
    let phase2_above = AtomicUsize::new(0);
    let mut candidate_pairs: Vec<(f64, &Id, &Id)> = graph1
        .nodes
        .par_iter()
        .filter(|(_, n)| n.total_weight >= config.min_features_for_lsh)
        .flat_map_iter(|(node_id1, node1)| {
            let mut query_buf: Vec<&Id> = Vec::with_capacity(128);
            lsh.query(&node1.signature, &mut query_buf);
            phase2_total.fetch_add(query_buf.len(), Ordering::Relaxed);
            let mut out = Vec::with_capacity(query_buf.len());
            for node_id2 in query_buf {
                let Some(node2) = graph2.nodes.get(node_id2) else {
                    continue;
                };
                let intersection = node1.signature_intersection(node2);
                let sim = intersection as f64 / config.k_permutations as f64;
                if sim >= config.anchor_threshold {
                    out.push((sim, node_id1, node_id2));
                }
            }
            phase2_above.fetch_add(out.len(), Ordering::Relaxed);
            out
        })
        .collect();
    stats.phase2.lsh_candidates = phase2_total.into_inner();
    stats.phase2.above_anchor = phase2_above.into_inner();

    // --- PHASE 3: Greedy Anchor Resolution ---
    // Parallel sort by (descending similarity, ascending id1, ascending id2).
    // Ties broken deterministically.
    candidate_pairs.par_sort_unstable_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.cmp(b.1))
            .then_with(|| a.2.cmp(b.2))
    });
    let mut propagation_queue = VecDeque::with_capacity(candidate_pairs.len());

    for (sim, node1, node2) in candidate_pairs {
        if final_matches.contains_key(node1) {
            stats.phase3.skip_a_taken += 1;
            continue;
        }
        if matched_graph2.contains(node2) {
            stats.phase3.skip_b_taken += 1;
            continue;
        }
        final_matches.insert(
            node1.clone(),
            Match {
                target: node2.clone(),
                similarity: sim,
            },
        );
        matched_graph2.insert(node2.clone());
        propagation_queue.push_back((node1.clone(), node2.clone()));
        stats.phase3.confirmed += 1;
    }

    // --- PHASE 4: Graph Propagation ---
    while let Some((node1, node2)) = propagation_queue.pop_front() {
        let mut propagate = |n1_opt: Option<&Vec<Id>>,
                             n2_opt: Option<&Vec<Id>>,
                             stats: &mut MatchStats| {
            if let (Some(n1_list), Some(n2_list)) = (n1_opt, n2_opt) {
                stats.phase4.propose += 1;
                // Hub filter — symmetric (default) skips when either side is
                // a hub; asymmetric skips only when BOTH sides are hubs (i.e.
                // the smaller side also exceeds max_degree). Asymmetric
                // accepts paths where one side is hub-inflated by inlining
                // asymmetry but the other isn't.
                let block = if config.asymmetric_hub_gate {
                    n1_list.len() > config.max_propagation_degree
                        && n2_list.len() > config.max_propagation_degree
                } else {
                    n1_list.len() > config.max_propagation_degree
                        || n2_list.len() > config.max_propagation_degree
                };
                if block {
                    stats.phase4.blocked_hub += 1;
                    return;
                }

                for n1 in n1_list {
                    if final_matches.contains_key(n1) {
                        stats.phase4.skip_a_taken += 1;
                        continue;
                    }
                    // Hold the `&Node` across the inner n2 loop so we don't
                    // re-probe `graph1.nodes` once per n2 candidate. Saves
                    // ~1M HashMap probes per pass.
                    let Some(node1_ref) = graph1.nodes.get(n1) else {
                        continue;
                    };
                    let size1 = node1_ref.total_weight;

                    let mut best_n2 = None;
                    let mut best_sim = -1.0;

                    for n2 in n2_list {
                        if matched_graph2.contains(n2) {
                            stats.phase4.skip_b_taken += 1;
                            continue;
                        }
                        let Some(node2_ref) = graph2.nodes.get(n2) else {
                            continue;
                        };
                        let size2 = node2_ref.total_weight;

                        // Size mismatch filter
                        let size_ratio = size1.max(size2) as f32 / size1.min(size2).max(1) as f32;
                        if size_ratio > config.size_mismatch_ratio {
                            stats.phase4.blocked_size += 1;
                            continue;
                        }

                        let intersection = node1_ref.signature_intersection(node2_ref);
                        let sim = intersection as f64 / config.k_permutations as f64;

                        // Optimal Match Selection: Find the highest similarity sibling
                        if sim >= config.propagation_threshold && sim > best_sim {
                            best_sim = sim;
                            best_n2 = Some(n2);
                        } else if sim < config.propagation_threshold {
                            stats.phase4.below_threshold += 1;
                        }
                    }

                    if let Some(n2) = best_n2 {
                        final_matches.insert(
                            n1.clone(),
                            Match {
                                target: n2.clone(),
                                similarity: best_sim,
                            },
                        );
                        matched_graph2.insert(n2.clone());
                        propagation_queue.push_back((n1.clone(), n2.clone()));
                        stats.phase4.confirmed += 1;
                    }
                }
            }
        };

        propagate(
            graph1.dependencies.get(&node1),
            graph2.dependencies.get(&node2),
            &mut stats,
        );
        propagate(
            graph1.dependents.get(&node1),
            graph2.dependents.get(&node2),
            &mut stats,
        );
    }

    (final_matches, stats)
}
