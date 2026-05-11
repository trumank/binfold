use std::hash::BuildHasher;

use rayon::prelude::*;
use rustc_hash::{FxBuildHasher, FxHashMap};

/// A band-fingerprint index over MinHash signatures.
///
/// For each of `lsh_bands` bands, the constructor hashes the band's signature
/// slice and retains an entry **only if exactly one node hashed to that
/// value**. Bands where two or more nodes collide on the same band-hash are
/// non-discriminative — those entries are dropped entirely so the query path
/// can treat each band's map as a unique-fingerprint lookup.
///
/// This is intentionally not classic LSH retrieval: there is no within-band
/// AND across rows beyond the band-hash itself, and no S-curve tunable via
/// (rows × bands). It pairs cleanly with downstream graph-propagation matchers
/// where Phase 2 needs cheap, high-precision anchors rather than approximate-NN
/// recall — empirically, on signatures with sparse-feature placeholder
/// collisions, the strict-singleton variant is a strict Pareto win on both
/// precision and recall vs. wider bucket caps.
pub struct LshIndex<Id> {
    bands: Vec<FxHashMap<u64, Id>>,
}

impl<Id> LshIndex<Id> {
    /// Build from `(node_id, signature)` pairs. For each band, hash the
    /// corresponding signature slice. The first node seen at a given hash
    /// claims the slot; any subsequent node colliding on the same band-hash
    /// invalidates the slot (no node wins — both are dropped from this band's
    /// index). At end, only band slots with exactly one originator remain.
    pub fn new<'a, Iter>(entries: Iter, lsh_bands: usize) -> Self
    where
        Id: Clone + Send + Sync,
        Iter: IntoIterator<Item = (Id, &'a [u64])>,
    {
        let entries: Vec<(Id, &[u64])> = entries.into_iter().collect();
        let rows_per_band = if entries.is_empty() || lsh_bands == 0 {
            0
        } else {
            entries[0].1.len() / lsh_bands
        };

        // Per-band parallel build. Each thread scans every entry against its
        // band; `Some(id)` = single owner so far, `None` = collided/dropped.
        // After the sweep, filter out `None` slots and unwrap to produce the
        // final unique-fingerprint map.
        let bands: Vec<FxHashMap<u64, Id>> = (0..lsh_bands)
            .into_par_iter()
            .map(|band_idx| {
                let mut tmp: FxHashMap<u64, Option<Id>> =
                    FxHashMap::with_capacity_and_hasher(entries.len(), FxBuildHasher);
                let start = band_idx * rows_per_band;
                for (key, signature) in &entries {
                    let hash = FxBuildHasher.hash_one(&signature[start..start + rows_per_band]);
                    tmp.entry(hash)
                        .and_modify(|slot| *slot = None)
                        .or_insert_with(|| Some(key.clone()));
                }
                tmp.into_iter()
                    .filter_map(|(k, v)| v.map(|id| (k, id)))
                    .collect()
            })
            .collect();

        Self { bands }
    }

    /// Look up candidate node identifiers from the union of band-fingerprint
    /// hits. Each band contributes 0 or 1 candidate; the output is sorted
    /// and deduplicated. The provided `candidates` buffer is cleared first
    /// so callers can reuse it across queries without allocator churn.
    pub fn query(&self, signature: &[u64], candidates: &mut Vec<Id>)
    where
        Id: Clone + Ord,
    {
        candidates.clear();
        if self.bands.is_empty() {
            return;
        }
        let lsh_rows = signature.len() / self.bands.len();

        for band_idx in 0..self.bands.len() {
            let start = band_idx * lsh_rows;
            let bucket_hash = FxBuildHasher.hash_one(&signature[start..start + lsh_rows]);
            if let Some(id) = self.bands[band_idx].get(&bucket_hash) {
                candidates.push(id.clone());
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_singleton_fingerprint_query() {
        // 12-element signatures, 3 bands of 4 rows. sig1 and sig2 share
        // bands 0 and 2 (rows [1,2,3,4] and [9,10,11,12]) — those bands
        // collide and are dropped. sig1 is unique in band 1.
        let sig1 = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let sig2 = vec![1, 2, 3, 4, 0, 0, 0, 0, 9, 10, 11, 12];
        let sig3 = vec![99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99];

        let entries = vec![
            (100, sig1.as_slice()),
            (200, sig2.as_slice()),
            (300, sig3.as_slice()),
        ];
        let index = LshIndex::new(entries, 3);

        let mut buf = Vec::new();

        index.query(&sig1, &mut buf);
        assert_eq!(buf, vec![100], "only band 1 is a fingerprint for sig1");

        index.query(&sig3, &mut buf);
        assert_eq!(
            buf,
            vec![300],
            "sig3 is unique in every band — dedup gives one hit"
        );
    }

    #[test]
    fn test_colliding_band_is_dropped() {
        // Three identical signatures collide on the single band's bucket →
        // bucket has >1 owner → dropped → query returns nothing.
        let sig = vec![1u64, 2, 3, 4];
        let entries = vec![
            (10, sig.as_slice()),
            (20, sig.as_slice()),
            (30, sig.as_slice()),
        ];
        let index = LshIndex::new(entries, 1);

        let mut buf = Vec::new();
        index.query(&sig, &mut buf);
        assert!(
            buf.is_empty(),
            "collided bucket should be dropped from the index"
        );
    }
}
