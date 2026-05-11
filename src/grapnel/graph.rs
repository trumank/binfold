use std::cmp::Ordering;
use std::hash::Hash;

use rayon::prelude::*;
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::hash::BuildHasher;

use super::min_hash::{Feature, UniversalMinHash};

/// The topological and structural representation of a graph.
///
/// The [`Graph`] tracks all parsed nodes (`nodes`) and their dependency
/// relationships (`dependents` and `dependencies`). It serves as the base data structure
/// for both structural hashing (LSH) and neighborhood-based graph propagation.
#[derive(Default, Debug)]
pub struct Graph<Id> {
    /// Map of identifiers to [`Node`]s.
    pub(super) nodes: FxHashMap<Id, Node>,
    /// Downward edges (node identifier to dependencies).
    pub(super) dependencies: FxHashMap<Id, Vec<Id>>,
    /// Upward edges (node identifier to dependents).
    pub(super) dependents: FxHashMap<Id, Vec<Id>>,
}

impl<Id> Graph<Id> {
    /// Inserts a new node into the graph.
    ///
    /// Sign many nodes in parallel. Each feature iterator is consumed twice:
    /// once collected into a vec to feed both MinHash signing and the
    /// `(hash, weight)` capture for the exact-Jaccard feature array. Signing
    /// is the dominant cost of building a graph (K permutations per feature
    /// weight unit), and each node is independent — fan it out across cores,
    /// then insert serially.
    pub fn add_nodes_par<I, FB>(&mut self, items: I, minhasher: &UniversalMinHash)
    where
        Id: Eq + Hash + Send,
        I: IntoParallelIterator<Item = (Id, FB)>,
        FB: IntoIterator + Send,
        FB::Item: Feature,
    {
        let signed: Vec<(Id, Node)> = items
            .into_par_iter()
            .map(|(key, features)| {
                let collected: Vec<_> = features.into_iter().collect();
                let mut pairs: Vec<(u64, u32)> = collected
                    .iter()
                    .map(|f| (FxBuildHasher.hash_one(f), f.weight()))
                    .collect();
                pairs.sort_unstable_by_key(|(h, _)| *h);
                pairs.dedup_by(|a, b| {
                    if a.0 == b.0 {
                        b.1 = b.1.max(a.1);
                        true
                    } else {
                        false
                    }
                });
                let (signature, total_weight) = minhasher.generate_signature(collected);
                (
                    key,
                    Node {
                        signature,
                        total_weight,
                        features: pairs.into_boxed_slice(),
                    },
                )
            })
            .collect();
        self.nodes.reserve(signed.len());
        for (key, node) in signed {
            self.nodes.insert(key, node);
        }
    }

    /// Bulk-insert pre-signed nodes. Used by callers that maintain
    /// incremental signatures across iterations (cache the stable baseline
    /// once, layer dynamic features per pass) and don't want the wrapper
    /// to re-run MinHash from raw features.
    pub fn insert_nodes(&mut self, items: impl IntoIterator<Item = (Id, Node)>)
    where
        Id: Eq + Hash,
    {
        for (key, node) in items {
            self.nodes.insert(key, node);
        }
    }

    /// Registers a directional edge from a dependent to a dependency.
    pub fn add_edge(&mut self, dependent: Id, dependency: Id)
    where
        Id: Clone + Eq + Hash,
    {
        self.dependencies
            .entry(dependent.clone())
            .or_default()
            .push(dependency.clone());
        self.dependents
            .entry(dependency)
            .or_default()
            .push(dependent);
    }
}

/// Represents a node within a graph.
///
/// Carries two complementary representations of the node's feature set:
///
/// - `signature`: the MinHash signature, used only by `LshIndex` to build the
///   band-fingerprint retrieval index. Each band slice is a u64 chunk of this
///   vector. No longer used for similarity scoring.
/// - `features`: the underlying `(feature_hash, weight)` pairs, sorted by
///   hash and deduplicated. Used for exact weighted Jaccard scoring in Phase
///   2 (anchor filtering) and Phase 4 (propagation sibling selection). The
///   exact computation has zero estimator variance — eliminating the
///   ±0.05-at-J=0.5 noise band that the MinHash estimator (K=800) inflicted
///   on every anchor-threshold decision.
#[derive(Debug)]
pub struct Node {
    pub(super) signature: Vec<u64>,
    pub(super) total_weight: u32,
    /// `(feature_hash, weight)` pairs sorted ascending by hash, deduplicated.
    /// Memory footprint is the dominant cost of carrying this — sweep your
    /// caller's feature-counts before assuming the trade is favourable.
    pub(super) features: Box<[(u64, u32)]>,
}

impl Node {
    /// Construct a `Node` from a pre-computed signature and the matching
    /// `(hash, weight)` feature pairs. The caller must supply `features` already
    /// sorted ascending by hash and deduplicated — `exact_weighted_jaccard`
    /// assumes that invariant. Used by callers that maintain incremental
    /// signatures across iterations (cached stable baseline + per-pass dynamic
    /// `update_signature` calls).
    #[inline]
    pub fn from_signature(
        signature: Vec<u64>,
        total_weight: u32,
        features: Box<[(u64, u32)]>,
    ) -> Self {
        debug_assert!(
            features.windows(2).all(|w| w[0].0 < w[1].0),
            "features must be sorted ascending by hash and deduplicated",
        );
        Self {
            signature,
            total_weight,
            features,
        }
    }

    /// Exact weighted Jaccard similarity between two nodes.
    ///
    /// Sorted merge over the two `(hash, weight)` arrays. Returns
    /// `intersect_weight / union_weight` with min/max accumulation per feature
    /// (the canonical weighted-Jaccard definition; reduces to "shared weight /
    /// union weight" when the same feature has the same weight on both sides,
    /// which is the case for callers whose weight is a pure function of the
    /// feature variant).
    ///
    /// Returns `0.0` when both sides have empty feature sets.
    #[inline]
    pub fn exact_weighted_jaccard(&self, other: &Node) -> f64 {
        let (a, b) = (&self.features, &other.features);
        let (mut i, mut j) = (0usize, 0usize);
        let (mut intersect, mut union) = (0u64, 0u64);
        while i < a.len() && j < b.len() {
            match a[i].0.cmp(&b[j].0) {
                Ordering::Less => {
                    union += a[i].1 as u64;
                    i += 1;
                }
                Ordering::Greater => {
                    union += b[j].1 as u64;
                    j += 1;
                }
                Ordering::Equal => {
                    let (wa, wb) = (a[i].1 as u64, b[j].1 as u64);
                    intersect += wa.min(wb);
                    union += wa.max(wb);
                    i += 1;
                    j += 1;
                }
            }
        }
        while i < a.len() {
            union += a[i].1 as u64;
            i += 1;
        }
        while j < b.len() {
            union += b[j].1 as u64;
            j += 1;
        }
        if union == 0 {
            0.0
        } else {
            intersect as f64 / union as f64
        }
    }
}
