use crate::pe_loader::{AnalysisCache, PeLoader};
use crate::warp;
use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct JsonBlock {
    pub start: u64,
    pub end: u64,
    pub guid: String,
}

#[derive(Debug, Deserialize)]
pub struct JsonFunction {
    pub start: u64,
    pub blocks: Vec<JsonBlock>,
    pub guid: String,
}

#[derive(Debug, Deserialize)]
pub struct JsonExe {
    pub path: String,
    pub functions: Vec<JsonFunction>,
}

pub fn load_expected_analysis<P: AsRef<Path>>(json_path: P) -> Result<Vec<JsonExe>> {
    let content = std::fs::read(json_path)?;
    Ok(serde_json::from_slice(&content)?)
}

pub fn compare_analysis(
    expected: &JsonExe,
    actual_functions: &[crate::pe_loader::FunctionAnalysis],
    pe: &PeLoader,
    cache: &AnalysisCache,
) {
    println!("\n=== Function Analysis Comparison ===");

    // Function count comparison
    println!(
        "Functions: {} expected, {} found",
        expected.functions.len(),
        actual_functions.len()
    );

    if expected.functions.len() != actual_functions.len() {
        println!("  ❌ Function count mismatch!");
    } else {
        println!("  ✅ Function count matches");
    }

    // Entry point comparison
    let expected_entry_points: HashSet<u64> = expected.functions.iter().map(|f| f.start).collect();
    let actual_entry_points: HashSet<u64> =
        actual_functions.iter().map(|f| f.entry_point).collect();

    let matching_entry_points = expected_entry_points
        .intersection(&actual_entry_points)
        .count();
    let extra_entry_points: Vec<u64> = actual_entry_points
        .difference(&expected_entry_points)
        .copied()
        .collect();

    println!(
        "Entry Points: {} matching out of {} expected",
        matching_entry_points,
        expected.functions.len()
    );

    if !extra_entry_points.is_empty() {
        println!("  Extra entry points ({}):", extra_entry_points.len());
        for addr in &extra_entry_points {
            println!("    0x{:x}", addr);
        }
    }

    // Create lookup map for actual functions and initialize GUID tracking
    let actual_functions_map: HashMap<u64, &crate::pe_loader::FunctionAnalysis> = actual_functions
        .iter()
        .map(|f| (f.entry_point, f))
        .collect();

    let mut total_function_guid_matches = 0;
    let mut total_block_guid_matches = 0;

    // Block-level comparison
    let mut total_expected_blocks = 0;
    let mut total_actual_blocks = 0;
    let mut total_matching_blocks = 0;
    let mut functions_with_block_mismatches = 0;

    println!("\n=== Block-Level Analysis ===");

    for expected_func in &expected.functions {
        let expected_blocks: HashSet<(u64, u64)> = expected_func
            .blocks
            .iter()
            .map(|b| (b.start, b.end))
            .collect();

        total_expected_blocks += expected_blocks.len();

        if let Some(actual_func) = actual_functions_map.get(&expected_func.start) {
            let actual_blocks: HashSet<(u64, u64)> = actual_func
                .basic_blocks
                .iter()
                .map(|(&start, &end)| (start, end))
                .collect();

            total_actual_blocks += actual_blocks.len();

            let matching_blocks = expected_blocks.intersection(&actual_blocks).count();
            total_matching_blocks += matching_blocks;

            let missing_blocks: Vec<(u64, u64)> = expected_blocks
                .difference(&actual_blocks)
                .copied()
                .collect();
            let extra_blocks: Vec<(u64, u64)> = actual_blocks
                .difference(&expected_blocks)
                .copied()
                .collect();

            // Check function GUID
            let mut function_guid_mismatch = false;
            let mut computed_function_guid_str = String::new();
            match warp::compute_function_guid(pe, cache, expected_func.start) {
                Ok(computed_guid) => {
                    computed_function_guid_str = computed_guid.to_string();
                    if computed_function_guid_str == expected_func.guid {
                        total_function_guid_matches += 1;
                    } else {
                        function_guid_mismatch = true;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Failed to compute GUID for function 0x{:x}: {}",
                        expected_func.start, e
                    );
                }
            }

            // Check if this function has block mismatches or GUID mismatch
            if expected_blocks.len() != actual_blocks.len()
                || !missing_blocks.is_empty()
                || !extra_blocks.is_empty()
                || function_guid_mismatch
            {
                functions_with_block_mismatches += 1;

                println!("\nFunction 0x{:x}:", expected_func.start);

                // Show function GUID info if there's a mismatch
                if function_guid_mismatch {
                    println!("  Function GUID mismatch:");
                    println!("    Expected: {}", expected_func.guid);
                    println!("    Computed: {}", computed_function_guid_str);
                }

                println!(
                    "  Expected blocks: {}, Actual blocks: {}, Matching: {}",
                    expected_blocks.len(),
                    actual_blocks.len(),
                    matching_blocks
                );

                if !missing_blocks.is_empty() {
                    println!("  Missing blocks ({}):", missing_blocks.len());
                    for (start, end) in &missing_blocks {
                        println!("    0x{:x}-0x{:x} (size: 0x{:x})", start, end, end - start);
                    }
                }

                if !extra_blocks.is_empty() {
                    println!("  Extra blocks ({}):", extra_blocks.len());
                    for (start, end) in &extra_blocks {
                        println!("    0x{:x}-0x{:x} (size: 0x{:x})", start, end, end - start);
                    }
                }

                // Check block GUIDs for this function
                let expected_block_guids: HashMap<(u64, u64), String> = expected_func
                    .blocks
                    .iter()
                    .map(|b| ((b.start, b.end), b.guid.clone()))
                    .collect();

                if let Ok(raw_bytes) = pe.read_at_va(actual_func.entry_point, actual_func.size) {
                    let base = actual_func.entry_point;
                    let mut block_guid_mismatches: Vec<(
                        u64,
                        u64,
                        String,
                        String,
                        warp::DetailedBlockAnalysis,
                    )> = Vec::new();

                    for (&start, &end) in &actual_func.basic_blocks {
                        if let Some(expected_guid) = expected_block_guids.get(&(start, end)) {
                            let block_start_offset = (start - base) as usize;
                            let block_end_offset = (end - base) as usize;
                            let block_bytes = &raw_bytes[block_start_offset..block_end_offset];

                            let computed_block_guid = warp::create_basic_block_guid(
                                block_bytes,
                                start,
                                actual_func.entry_point
                                    ..(actual_func.entry_point + actual_func.size as u64),
                                pe,
                            );
                            let computed_guid_str = computed_block_guid.to_string();

                            if computed_guid_str == *expected_guid {
                                total_block_guid_matches += 1;
                            } else {
                                // Get detailed analysis for mismatched block
                                let detailed_analysis = warp::create_detailed_basic_block_analysis(
                                    block_bytes,
                                    start,
                                    actual_func.entry_point
                                        ..(actual_func.entry_point + actual_func.size as u64),
                                    pe,
                                );
                                block_guid_mismatches.push((
                                    start,
                                    end,
                                    expected_guid.clone(),
                                    computed_guid_str,
                                    detailed_analysis,
                                ));
                            }
                        }
                    }

                    if !block_guid_mismatches.is_empty() {
                        println!("  Block GUID mismatches ({}):", block_guid_mismatches.len());
                        for (start, end, expected, computed, detailed_analysis) in
                            &block_guid_mismatches
                        {
                            println!("    0x{:x}-0x{:x}:", start, end);
                            println!("      Expected: {}", expected);
                            println!("      Computed: {}", computed);
                            println!("      Disassembly:");
                            for instruction in &detailed_analysis.instructions {
                                let mask_info = if instruction.was_masked {
                                    format!(
                                        " [MASKED: {}]",
                                        instruction
                                            .mask_reason
                                            .as_ref()
                                            .unwrap_or(&"unknown".to_string())
                                    )
                                } else {
                                    " [KEPT]".to_string()
                                };
                                println!(
                                    "        0x{:08x}: {:02x?} {}{}",
                                    instruction.address,
                                    instruction.bytes,
                                    instruction.disassembly,
                                    mask_info
                                );
                            }
                        }
                    }
                }
            } else {
                // No block mismatches, but still need to check function GUID
                match warp::compute_function_guid(pe, cache, expected_func.start) {
                    Ok(computed_guid) => {
                        let computed_function_guid_str = computed_guid.to_string();
                        if computed_function_guid_str == expected_func.guid {
                            total_function_guid_matches += 1;
                        } else {
                            // Function GUID mismatch but no block issues
                            println!("\nFunction 0x{:x}:", expected_func.start);
                            println!("  Function GUID mismatch:");
                            println!("    Expected: {}", expected_func.guid);
                            println!("    Computed: {}", computed_function_guid_str);
                            println!(
                                "  Expected blocks: {}, Actual blocks: {}, Matching: {}",
                                expected_blocks.len(),
                                actual_blocks.len(),
                                matching_blocks
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Failed to compute GUID for function 0x{:x}: {}",
                            expected_func.start, e
                        );
                    }
                }
            }
        }
    }

    // Summary
    println!("\n=== Summary ===");
    println!(
        "Basic Blocks: {} expected, {} found, {} matching",
        total_expected_blocks, total_actual_blocks, total_matching_blocks
    );

    println!(
        "Function GUIDs: {} matching out of {} expected",
        total_function_guid_matches,
        expected.functions.len()
    );

    println!("Basic Block GUIDs: {} matching", total_block_guid_matches);

    if functions_with_block_mismatches > 0 {
        println!(
            "  ❌ {} functions have block mismatches",
            functions_with_block_mismatches
        );
    } else {
        println!("  ✅ All functions have matching blocks");
    }

    // Percentage statistics
    println!("\n=== Percentage Statistics ===");

    // Function match percentage
    let function_match_percentage = if !expected.functions.is_empty() {
        (matching_entry_points as f64 / expected.functions.len() as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "Function Match Rate: {:.1}% ({}/{})",
        function_match_percentage,
        matching_entry_points,
        expected.functions.len()
    );

    // Block match percentage
    let block_match_percentage = if total_expected_blocks > 0 {
        (total_matching_blocks as f64 / total_expected_blocks as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "Block Match Rate: {:.1}% ({}/{})",
        block_match_percentage, total_matching_blocks, total_expected_blocks
    );

    // Function with perfect block matches
    let perfect_functions = expected.functions.len() - functions_with_block_mismatches;
    let perfect_function_percentage = if !expected.functions.is_empty() {
        (perfect_functions as f64 / expected.functions.len() as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "Perfect Function Match Rate: {:.1}% ({}/{})",
        perfect_function_percentage,
        perfect_functions,
        expected.functions.len()
    );

    // GUID match percentage
    let function_guid_percentage = if !expected.functions.is_empty() {
        (total_function_guid_matches as f64 / expected.functions.len() as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "Function GUID Match Rate: {:.1}% ({}/{})",
        function_guid_percentage,
        total_function_guid_matches,
        expected.functions.len()
    );

    // Block GUID match percentage
    let total_expected_block_guids: usize = expected.functions.iter().map(|f| f.blocks.len()).sum();
    let block_guid_percentage = if total_expected_block_guids > 0 {
        (total_block_guid_matches as f64 / total_expected_block_guids as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "Block GUID Match Rate: {:.1}% ({}/{})",
        block_guid_percentage, total_block_guid_matches, total_expected_block_guids
    );
}
