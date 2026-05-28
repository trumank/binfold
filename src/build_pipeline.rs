//! Shared GUID + constraint pipeline used by every gen-db symbol source.
//!
//! Symbol sources differ (PDB on PE, `.dynsym` on ELF, others later) but the
//! downstream work is identical:
//!
//! 1. For every address with a known name, run the WARP analysis to get a
//!    function GUID and the child-call / data-ref constraints derived
//!    purely from code shape.
//! 2. Build a reverse call-graph map to derive parent-call constraints.
//! 3. Augment each function's constraint list with symbol-keyed constraints
//!    on both directions of every direct call.
//!
//! That pipeline is the function below; symbol-source modules just supply
//! the `name_by_addr` map and the per-binary mmap.

use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;

use crate::ProgressReporter;
use crate::binary::{AnalysisCache, Binary};
use crate::db::{ConstraintGuid, DbHash, FunctionGuid, SymbolGuid};
use crate::warp::{Constraint, compute_function_guid_with_contraints};

/// One named function with its derived GUID and full constraint list.
#[derive(Default, Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub size: Option<u32>,
    pub guid: FunctionGuid,
    pub constraints: Vec<Constraint<DbHash>>,
}

/// Reverse call graph: callee VA -> `[(caller VA, call-site offset within
/// the caller)]`.
///
/// The offset convention (`call.address - caller`) is the one every
/// call-edge-keyed constraint uses, so building the map in a single place
/// keeps the gen-db and analyze sides in lockstep: a parent-call constraint
/// emitted at build time and one queried at analyze time carry the same
/// offset.
///
/// `addresses` must be functions already present in `cache` (all callers in
/// every use site are analyzed functions); `cache.get` is therefore
/// unwrapped.
pub fn build_caller_map(
    addresses: impl IntoIterator<Item = u64>,
    cache: &AnalysisCache,
    bin: &Binary,
) -> HashMap<u64, Vec<(u64, u64)>> {
    let mut callers: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
    for caller in addresses {
        let analysis = cache.get(caller, bin).unwrap();
        for call in &analysis.calls {
            callers
                .entry(call.target)
                .or_default()
                .push((caller, call.address - caller));
        }
    }
    callers
}

/// Streaming form: each `FunctionInfo` is delivered to `emit` and dropped
/// before the next one is produced, so the producer's working set stays
/// bounded by the call-graph maps rather than holding every `FunctionInfo`
/// at once.
pub fn process_named_functions_streaming<P, F>(
    bin: &Binary,
    name_by_addr: &HashMap<u64, String>,
    progress_reporter: Option<P>,
    mut emit: F,
) -> Result<()>
where
    P: ProgressReporter,
    F: FnMut(FunctionInfo),
{
    let cache = AnalysisCache::default();

    if let Some(reporter) = &progress_reporter {
        reporter.initialize(name_by_addr.len() as u64);
    }

    // Pass 1: per-address WARP analysis. Yields the function GUID and the
    // code-shape constraints (child calls, data const). Symbol-keyed
    // constraints come later once every function in this binary has a name
    // bound to its address.
    let mut functions: HashMap<u64, FunctionInfo> = name_by_addr
        .par_iter()
        .map(|(&address, name)| -> Result<_> {
            let func = compute_function_guid_with_contraints::<DbHash>(bin, &cache, address)?;
            let analysis = cache.get(address, bin).unwrap();
            let info = FunctionInfo {
                name: name.clone(),
                address,
                size: Some(analysis.size as u32),
                guid: func.guid,
                constraints: func.constraints,
            };
            if let Some(reporter) = &progress_reporter {
                reporter.progress();
            }
            Ok((address, info))
        })
        .collect::<Result<_>>()?;

    if let Some(reporter) = progress_reporter {
        reporter.finish();
    }

    // Pass 2: build the reverse call-graph for parent constraints.
    let callers = build_caller_map(functions.keys().copied(), &cache, bin);

    // Pass 3: derive per-function symbol-keyed constraints. Each direct
    // call edge contributes a symbol-child-call (forward) and, on the
    // callee side, a symbol-parent-call + function-parent-call (reverse).
    // Function-child-call constraints are already in the per-function set
    // from pass 1; this only adds the symbol-keyed flavors.
    let constraints: Vec<_> = functions
        .par_iter()
        .map(|(address, _info)| {
            let mut constraints = Vec::new();
            let analysis = cache.get(*address, bin).unwrap();

            for call in &analysis.calls {
                if let Some(target_fn) = functions.get(&call.target) {
                    let offset = Some((call.address - address) as i64);
                    let target_symbol = SymbolGuid::from_symbol(&target_fn.name);
                    constraints.push(Constraint {
                        guid: ConstraintGuid::from_symbol_child_call(target_symbol),
                        offset,
                    });
                }
            }

            if let Some(parent_calls) = callers.get(address) {
                for (parent_addr, offset) in parent_calls {
                    if let Some(parent_fn) = functions.get(parent_addr) {
                        let offset = Some(*offset as i64);
                        constraints.push(Constraint {
                            guid: ConstraintGuid::from_parent_call(parent_fn.guid),
                            offset,
                        });
                        let parent_symbol = SymbolGuid::from_symbol(&parent_fn.name);
                        constraints.push(Constraint {
                            guid: ConstraintGuid::from_symbol_parent_call(parent_symbol),
                            offset,
                        });
                    }
                }
            }
            (*address, constraints)
        })
        .collect();

    // Cache + reverse map are no longer needed; drop before the emit phase
    // so their heap (and the cache's Arc<FunctionAnalysis>s) is freed.
    drop(cache);
    drop(callers);

    for (address, c) in constraints {
        functions.get_mut(&address).unwrap().constraints.extend(c);
    }

    // Stream each FunctionInfo out so callers can merge and drop it before
    // the next entry is produced. Avoids the duplicate Vec peak.
    for (_, info) in functions {
        emit(info);
    }

    Ok(())
}
