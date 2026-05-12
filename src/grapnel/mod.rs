//! Thin re-export of the external [`grapnel`] crate. Kept as a module so
//! existing `binfold::grapnel::X` import paths in binaries (notably
//! `bin/fuzzy_match.rs`) keep working without changes.

pub use ::grapnel::{Feature, Graph, Match, MatcherConfig, Node, UniversalMinHash};
