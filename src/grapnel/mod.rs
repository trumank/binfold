//! Graph-propagation matcher for binary diffing.
//!
//! Previously a separate `grapnel` workspace crate; inlined into `binfold`
//! because the algorithm diverged enough from generic LSH+MinHash matching
//! (singleton-fingerprint retrieval, exact weighted Jaccard scoring, the
//! Phase 4 propagation gates) that maintaining a library boundary stopped
//! paying for itself. See `GRAPNEL.md` for the design history.

mod graph;
mod lsh;
mod matching;
mod min_hash;

pub use graph::{Graph, Node};
pub use matching::MatcherConfig;
pub use min_hash::{Feature, UniversalMinHash};
