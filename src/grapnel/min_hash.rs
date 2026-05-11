use std::hash::{BuildHasher, Hash};

use rustc_hash::FxBuildHasher;

/// A trait for extractable features, enabling stringless Weighted MinHashing.
pub trait Feature: Hash {
    /// Returns the feature's frequency or weight.
    fn weight(&self) -> u32;
}

/// Golden Ratio fractional part for Fibonacci hashing.
const FIBONACCI_HASH_MULTIPLIER: u64 = 0x9E37_79B9_7F4A_7C15;

/// Optimal 64-bit LCG multiplier (Knuth).
const KNUTH_LCG_MULTIPLIER: u64 = 6_364_136_223_846_793_005;

/// Generates Weighted MinHash signatures using a multiplicative hash family
/// over u64 (wrapping arithmetic). Equivalent in MinHash semantics to a
/// Carter–Wegman family with prime modulus, but the inner K-loop reduces
/// to one `vpmullq` + one `vpaddq` + one `vpcmpltuq` + masked `vmovdqu64`
/// per 8 K-lanes on AVX-512 DQ, vs the ~50 instructions per 8 lanes the
/// prime-modulus version compiled to (scalar `mulx` + GP→ZMM repacking).
///
/// Precomputes per-permutation coefficients (`a` odd over full u64
/// range, `b` arbitrary) once at construction.
pub struct UniversalMinHash {
    /// Multiplicative hash coefficients (`a` odd → bijective on u64).
    a: Vec<u64>,
    /// Additive hash coefficients (any u64).
    b: Vec<u64>,
    /// Number of permutations ($K$).
    k_permutations: usize,
}

impl UniversalMinHash {
    /// Initializes a deterministic MinHash generator using an unbiased LCG.
    ///
    /// # Arguments
    /// * `seed` - Seed for permutation polynomial generation.
    /// * `k_permutations` - Number of permutations ($K$).
    pub fn new(mut seed: u64, k_permutations: usize) -> Self {
        let mut a = Vec::with_capacity(k_permutations);
        let mut b = Vec::with_capacity(k_permutations);

        // Deterministic LCG with Rejection Sampling to perfectly eliminate Modulo Bias
        let limit = u64::MAX - 7;
        let mut next_unbiased = || loop {
            seed = seed.wrapping_mul(KNUTH_LCG_MULTIPLIER).wrapping_add(1);
            if seed <= limit {
                return seed;
            }
        };

        // Multiplicative-hash variant: `a` odd over the full 64-bit range
        // (force lowest bit set), `b` arbitrary 64-bit. The hash family is
        // `h_i(x) = a[i].wrapping_mul(x).wrapping_add(b[i])` — uniform in
        // the high bits when a is odd and x is well-mixed, and crucially
        // the inner loop auto-vectorizes to `vpmullq` + `vpaddq` on AVX-512
        // DQ (no 64×64→128 multiply needed). See change-log entry on K-loop
        // SIMD rewrite.
        for _ in 0..k_permutations {
            a.push(next_unbiased() | 1); // a odd, full u64 range
            b.push(next_unbiased());
        }
        Self {
            a,
            b,
            k_permutations,
        }
    }

    /// Number of permutations ($K$) in signatures produced by this hasher.
    #[inline]
    pub fn k(&self) -> usize {
        self.k_permutations
    }

    /// Computes a MinHash signature from an iterator of features.
    ///
    /// Features are "unrolled" proportionally to their weight using Fibonacci hashing
    /// to accurately approximate the weighted Jaccard similarity.
    ///
    /// # Returns
    /// A tuple containing:
    /// 1. The $K$-length signature vector.
    /// 2. The total sum of feature weights, which can be used to filter out noisy/small nodes.
    pub fn generate_signature<I>(&self, features: I) -> (Vec<u64>, u32)
    where
        I: IntoIterator,
        I::Item: Feature,
    {
        // Multiplicative-hash MinHash: mins start at u64::MAX (the
        // "infinity" sentinel for unsigned min). Each `(a[i]*x+b[i])
        // wrapping mod 2^64` is a uniformly-distributed u64 over the
        // signature index space.
        let mut mins = vec![u64::MAX; self.k_permutations];
        let total_weight = self.update_signature(&mut mins, features);
        (mins, total_weight)
    }

    /// Update an existing signature in-place by `min`-ing in additional
    /// features. Returns the sum of weights of the incoming features.
    ///
    /// Because `min` is commutative and associative, the result is
    /// bit-identical to passing the chain (already-applied + new) features
    /// through [`generate_signature`]. This is the building block for
    /// cached / incremental MinHash where a stable baseline signature is
    /// computed once and per-iteration dynamic features are layered on top.
    ///
    /// # Panics
    /// If `mins.len() != k_permutations`.
    pub fn update_signature<I>(&self, mins: &mut [u64], features: I) -> u32
    where
        I: IntoIterator,
        I::Item: Feature,
    {
        assert_eq!(
            mins.len(),
            self.k_permutations,
            "mins.len() must equal k_permutations"
        );
        let mut total_weight = 0;

        for feature in features {
            let weight = feature.weight();
            total_weight += weight;

            let base_hash = FxBuildHasher.hash_one(&feature);
            for w in 0..weight {
                let w_hash = (w as u64).wrapping_mul(FIBONACCI_HASH_MULTIPLIER);
                let x = base_hash ^ w_hash;

                // Tight K-loop — LLVM auto-vectorises this to AVX-512
                // `vpmullq` + `vpaddq` + `vpcmpltuq` + masked store on
                // `target-cpu=native` (no Mersenne reduction = no 64x64→128
                // multiply = no GP→ZMM repacking). The previous Carter–
                // Wegman version had ~50 instructions per 8 K-lanes; this
                // is ~6.
                for (i, min_val) in mins.iter_mut().enumerate().take(self.k_permutations) {
                    let val = self.a[i].wrapping_mul(x).wrapping_add(self.b[i]);
                    if val < *min_val {
                        *min_val = val;
                    }
                }
            }
        }
        total_weight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Hash, Clone)]
    struct TestFeature {
        name: String,
        weight: u32,
    }

    impl Feature for TestFeature {
        fn weight(&self) -> u32 {
            self.weight
        }
    }

    #[test]
    fn test_minhash_creation() {
        let k = 100;
        let mh = UniversalMinHash::new(12345, k);
        assert_eq!(mh.k_permutations, k);
        assert_eq!(mh.a.len(), k);
        assert_eq!(mh.b.len(), k);
    }

    #[test]
    fn test_generate_signature_length_and_weight() {
        let mh = UniversalMinHash::new(12345, 100);
        let features = vec![
            TestFeature {
                name: "feat_A".to_string(),
                weight: 3,
            },
            TestFeature {
                name: "feat_B".to_string(),
                weight: 2,
            },
        ];

        let (sig, total_weight) = mh.generate_signature(features);

        assert_eq!(sig.len(), 100);
        assert_eq!(total_weight, 5);
    }

    #[test]
    fn test_identical_features_identical_signatures() {
        let mh = UniversalMinHash::new(12345, 100);
        let features1 = vec![TestFeature {
            name: "feat_X".to_string(),
            weight: 1,
        }];
        let features2 = vec![TestFeature {
            name: "feat_X".to_string(),
            weight: 1,
        }];

        let (sig1, _) = mh.generate_signature(features1);
        let (sig2, _) = mh.generate_signature(features2);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_different_features_different_signatures() {
        let mh = UniversalMinHash::new(12345, 100);
        let features1 = vec![TestFeature {
            name: "feat_X".to_string(),
            weight: 1,
        }];
        let features2 = vec![TestFeature {
            name: "feat_Y".to_string(),
            weight: 1,
        }];

        let (sig1, _) = mh.generate_signature(features1);
        let (sig2, _) = mh.generate_signature(features2);

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_update_signature_equivalent_to_full_generate() {
        let mh = UniversalMinHash::new(0xCAFE_F00D, 256);
        let stable = vec![
            TestFeature {
                name: "bigram_a".into(),
                weight: 1,
            },
            TestFeature {
                name: "import_b".into(),
                weight: 8,
            },
            TestFeature {
                name: "string_c".into(),
                weight: 64,
            },
            TestFeature {
                name: "const_d".into(),
                weight: 4,
            },
        ];
        let dynamic = vec![
            TestFeature {
                name: "synt_callee_e".into(),
                weight: 16,
            },
            TestFeature {
                name: "fnptr_peer_f".into(),
                weight: 256,
            },
            TestFeature {
                name: "synt_callee_g".into(),
                weight: 8,
            },
        ];

        let full: Vec<TestFeature> = stable.iter().chain(dynamic.iter()).cloned().collect();
        let (sig_full, w_full) = mh.generate_signature(full);

        let (mut sig_inc, w_stable) = mh.generate_signature(stable.clone());
        let w_dyn = mh.update_signature(&mut sig_inc, dynamic.clone());

        assert_eq!(sig_full, sig_inc, "incremental signature must match full");
        assert_eq!(w_full, w_stable + w_dyn);

        // Order independence: applying dynamic in a different order also matches.
        let (mut sig_inc2, _) = mh.generate_signature(stable);
        let mut reversed = dynamic.clone();
        reversed.reverse();
        mh.update_signature(&mut sig_inc2, reversed);
        assert_eq!(sig_full, sig_inc2);
    }

    #[test]
    fn test_update_signature_empty_is_noop() {
        let mh = UniversalMinHash::new(7, 64);
        let stable = vec![TestFeature {
            name: "x".into(),
            weight: 2,
        }];
        let (sig_before, _) = mh.generate_signature(stable);
        let mut sig = sig_before.clone();
        let w = mh.update_signature(&mut sig, Vec::<TestFeature>::new());
        assert_eq!(sig, sig_before);
        assert_eq!(w, 0);
    }
}
