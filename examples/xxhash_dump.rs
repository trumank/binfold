//! Hash every function in a PE with xxhash-64 and print the results.
//!
//! Run with: `cargo run --example xxhash_dump -- path/to/binary.exe`

use std::fmt;

use anyhow::Result;
use binfold::hash::HashAlgo;
use binfold::pe_loader::{AnalysisCache, PeLoader};
use binfold::warp::{FunctionGuid, compute_function_guid};
use rayon::prelude::*;

struct XxHash64;

impl HashAlgo for XxHash64 {
    type Digest = u64;
    type Key = u64;

    const DIGEST_SIZE: usize = 8;

    fn oneshot(seed: u64, bytes: &[u8]) -> u64 {
        twox_hash::XxHash64::oneshot(seed, bytes)
    }
    fn key_from_name(name: &str) -> u64 {
        twox_hash::XxHash64::oneshot(0, name.as_bytes())
    }
    fn nil() -> u64 {
        0
    }
    fn digest_bytes(d: &u64) -> impl AsRef<[u8]> {
        d.to_le_bytes()
    }
    fn digest_from_bytes(bytes: &[u8]) -> u64 {
        u64::from_le_bytes(bytes.try_into().unwrap())
    }
    fn fmt_digest(d: &u64, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", d)
    }
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: xxhash_dump <exe>"))?;

    let pe = PeLoader::load(&path)?;
    let functions = pe.find_all_functions(&|msg| eprintln!("{msg}"))?;
    let cache = AnalysisCache::new(functions.iter().cloned());

    let mut hashes: Vec<(u64, FunctionGuid<XxHash64>)> = functions
        .par_iter()
        .filter_map(|f| {
            compute_function_guid::<XxHash64>(&pe, &cache, f.entry_point)
                .ok()
                .map(|g| (f.entry_point, g))
        })
        .collect();
    hashes.sort_by_key(|(addr, _)| *addr);

    for (addr, guid) in &hashes {
        println!("{:#018x}  {}", addr, guid);
    }
    eprintln!("{} functions", hashes.len());
    Ok(())
}
