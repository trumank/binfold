use std::hash::Hash;

use rayon::prelude::*;
use rustc_hash::FxHashMap;

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
    /// Sign many nodes in parallel. Signing is the dominant cost of building
    /// a graph (K hash permutations per feature weight unit), and each node
    /// is independent — fan it out across cores, then insert serially.
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
                let (signature, total_weight) = minhasher.generate_signature(features);
                (
                    key,
                    Node {
                        signature,
                        total_weight,
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

/// Represents a node within a graph. Holds the K-length MinHash signature
/// (used both as the source of LSH band fingerprints and for the
/// `signature_intersection / K` Jaccard estimate) plus the total feature
/// weight (gates LSH indexing via `min_features_for_lsh`).
#[derive(Debug)]
pub struct Node {
    pub(super) signature: Vec<u64>,
    pub(super) total_weight: u32,
}

impl Node {
    /// Construct a `Node` from a pre-computed MinHash signature and weight
    /// sum. Used by callers that maintain incremental signatures across
    /// iterations (cached stable baseline + per-pass dynamic
    /// `update_signature` calls) and want to insert pre-signed nodes via
    /// [`Graph::insert_nodes`].
    #[inline]
    pub fn from_signature(signature: Vec<u64>, total_weight: u32) -> Self {
        Self {
            signature,
            total_weight,
        }
    }

    /// Number of positions where two K-length MinHash signatures agree.
    /// `intersection / K` is an unbiased estimator of weighted Jaccard with
    /// std-dev ≈ √(J(1−J)/K). LLVM auto-vectorises this to AVX-512
    /// `vpcmpeqq` + reduce on `target-cpu=native`.
    #[inline]
    pub fn signature_intersection(&self, other: &Node) -> usize {
        self.signature
            .iter()
            .zip(other.signature.iter())
            .map(|(a, b)| (*a == *b) as usize)
            .sum()
    }
}
