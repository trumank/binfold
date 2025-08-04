use anyhow::{Result, Context};
use indicatif::{ProgressBar, ProgressIterator as _, ProgressStyle};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use crate::db::{Db, DbWriter};
use crate::warp::{Constraint, FunctionGuid};

/// Merges multiple Binfold databases into a single database.
/// 
/// This function takes multiple database files and combines them, deduplicating
/// strings and merging function constraints. Functions with the same GUID will
/// have their constraints combined.
/// 
/// # Arguments
/// 
/// * `input_paths` - Paths to input database files to merge
/// * `output_path` - Path where the merged database will be written
/// 
/// # Returns
/// 
/// Returns `Ok(())` on success, or an error if any operation fails.
pub fn merge_databases(input_paths: &[impl AsRef<Path>], output_path: &Path) -> Result<()> {
    // First pass: open and memory map all files
    let mut temp_storage = Vec::new();
    let mut skipped_files = Vec::new();
    
    for path in input_paths {
        let path_ref = path.as_ref();
        
        // Try to open the file
        let file = match File::open(path_ref) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Warning: Failed to open database '{}': {}. Skipping.", path_ref.display(), e);
                skipped_files.push((path_ref.to_path_buf(), format!("Failed to open: {}", e)));
                continue;
            }
        };
        
        // Try to memory map the file
        let mmap = match unsafe { memmap2::MmapOptions::new().map(&file) } {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Warning: Failed to memory map database '{}': {}. Skipping.", path_ref.display(), e);
                skipped_files.push((path_ref.to_path_buf(), format!("Memory map failed: {}", e)));
                continue;
            }
        };
        
        temp_storage.push((path_ref.to_path_buf(), file, mmap));
    }
    
    // Second pass: parse databases and keep only valid ones
    let mut valid_storage = Vec::new();
    
    for (path, file, mmap) in temp_storage {
        // Test if we can parse the database
        let test_db = Db::new(&mmap);
        
        match test_db {
            Ok(_) => {
                // Database is valid, keep it
                valid_storage.push((file, mmap));
            }
            Err(e) => {
                eprintln!("Warning: Failed to parse database '{}': {}. Skipping.", path.display(), e);
                skipped_files.push((path, format!("Parse failed: {}", e)));
            }
        }
    }
    
    // Check if we have enough valid databases to merge
    if valid_storage.len() < 2 {
        anyhow::bail!("Need at least 2 valid databases to merge. Found {} valid databases out of {} total files.", 
                      valid_storage.len(), input_paths.len());
    }
    
    // Now create the final structures
    let mut input_files = Vec::new();
    let mut input_mmaps = Vec::new();
    let mut input_dbs = Vec::new();
    
    for (file, mmap) in valid_storage {
        input_files.push(file);
        input_mmaps.push(mmap);
    }
    
    // Create all databases from the stored mmaps
    for mmap in &input_mmaps {
        let db = Db::new(mmap)?;
        input_dbs.push(db);
    }
    
    // Keep references to databases
    let dbs: Vec<&Db> = input_dbs.iter().collect();
    
    println!("Building string offset mappings...");
    let string_offset_maps: Vec<HashMap<u64, u64>> = dbs.iter()
        .map(|db| db.build_string_offset_to_index_map())
        .collect::<Result<Vec<_>>>()?;
    
    println!("Merging string tables...");
    let (merged_strings, string_remapping) = merge_string_tables(&dbs)?;
    
    println!("Merging functions...");
    let merged_functions = merge_functions(&dbs, &string_remapping, &string_offset_maps)?;
    
    println!("Writing merged database...");
    write_merged_database(output_path, &merged_functions, &merged_strings)?;
    
    // Print statistics
    let total_input_functions: usize = dbs.iter().map(|db| db.function_count()).sum();
    let total_input_strings: usize = dbs.iter().map(|db| db.string_count()).sum();
    let total_input_constraints: usize = dbs.iter().map(|db| db.constraint_count()).sum();
    
    println!("\nMerge Statistics:");
    println!("  Input databases: {}", input_paths.len());
    println!("  Valid databases processed: {}", dbs.len());
    if !skipped_files.is_empty() {
        println!("  Skipped files: {}", skipped_files.len());
        for (path, reason) in &skipped_files {
            println!("    - {}: {}", path.display(), reason);
        }
    }
    println!("  Total input functions: {}", total_input_functions);
    println!("  Merged unique functions: {}", merged_functions.len());
    println!("  Total input strings: {}", total_input_strings);
    println!("  Merged unique strings: {}", merged_strings.len());
    println!("  Total input constraints: {}", total_input_constraints);
    
    Ok(())
}

/// Merges string tables from multiple databases, deduplicating identical strings.
/// 
/// Returns a tuple of:
/// - The merged string table with unique strings
/// - Per-database remapping tables from old indices to new indices
fn merge_string_tables(dbs: &[&Db]) -> Result<(Vec<String>, Vec<HashMap<u64, u64>>)> {
    let mut merged_strings = Vec::new();
    let mut string_to_new_index: HashMap<String, u64> = HashMap::new();
    let mut string_remapping = Vec::new();
    
    let total_strings: usize = dbs.iter().map(|db| db.string_count()).sum();
    // Use checked cast to prevent overflow
    let pb_length = u64::try_from(total_strings)
        .unwrap_or(u64::MAX);
    let pb = ProgressBar::new(pb_length)
        .with_style(progress_style())
        .with_message("Processing strings");
    
    for db in dbs {
        let mut local_remapping = HashMap::new();
        
        for (old_idx, string) in db.iter_strings().enumerate().progress_with(pb.clone()) {
            let new_idx = if let Some(&existing_idx) = string_to_new_index.get(&string) {
                existing_idx
            } else {
                // Use checked arithmetic to prevent overflow
                let idx = u64::try_from(merged_strings.len())
                    .context("String table index overflow")?;
                merged_strings.push(string.clone());
                string_to_new_index.insert(string, idx);
                idx
            };
            
            let old_idx_u64 = u64::try_from(old_idx)
                .context("String index overflow")?;
            local_remapping.insert(old_idx_u64, new_idx);
        }
        
        string_remapping.push(local_remapping);
    }
    
    pb.finish_with_message(format!("Merged {} unique strings", merged_strings.len()));
    
    Ok((merged_strings, string_remapping))
}

/// Merges functions from multiple databases, combining constraints for functions
/// with the same GUID.
/// 
/// # Arguments
/// 
/// * `dbs` - The databases to merge
/// * `string_remapping` - Per-database string index remapping tables
/// * `string_offset_maps` - Per-database byte offset to index mapping tables
/// 
/// # Returns
/// 
/// A map from function GUIDs to their merged constraints and symbol references.
fn merge_functions(
    dbs: &[&Db],
    string_remapping: &[HashMap<u64, u64>],
    string_offset_maps: &[HashMap<u64, u64>],
) -> Result<BTreeMap<FunctionGuid, HashMap<Constraint, HashSet<u64>>>> {
    let mut merged_functions: BTreeMap<FunctionGuid, HashMap<Constraint, HashSet<u64>>> = BTreeMap::new();
    
    let total_functions: usize = dbs.iter().map(|db| db.function_count()).sum();
    // Use checked cast to prevent overflow
    let pb_length = u64::try_from(total_functions)
        .unwrap_or(u64::MAX);
    let pb = ProgressBar::new(pb_length)
        .with_style(progress_style())
        .with_message("Processing functions");
    
    for (db_idx, db) in dbs.iter().enumerate() {
        let local_string_remap = &string_remapping[db_idx];
        let local_offset_to_idx = &string_offset_maps[db_idx];
        
        for func_guid in db.iter_functions().progress_with(pb.clone()) {
            // Process constraints for this function
            process_function_constraints(
                db,
                func_guid,
                &mut merged_functions,
                local_string_remap,
                local_offset_to_idx,
            )?;
        }
    }
    
    pb.finish_with_message(format!("Merged {} unique functions", merged_functions.len()));
    
    // Remove any empty constraints that might have been created
    for constraints in merged_functions.values_mut() {
        constraints.retain(|_, strings| !strings.is_empty());
    }
    
    Ok(merged_functions)
}

/// Processes constraints for a single function during merge.
/// 
/// This helper function extracts the constraint processing logic to reduce nesting.
fn process_function_constraints(
    db: &Db,
    func_guid: FunctionGuid,
    merged_functions: &mut BTreeMap<FunctionGuid, HashMap<Constraint, HashSet<u64>>>,
    local_string_remap: &HashMap<u64, u64>,
    local_offset_to_idx: &HashMap<u64, u64>,
) -> Result<()> {
    let func_constraints = merged_functions.entry(func_guid).or_default();
    
    // Get raw constraint data with byte offsets
    if let Some((constraints, _string_ref_table)) = db.get_function_constraints_raw(func_guid)?{
        for (constraint, symbol_byte_offsets) in constraints {
            let constraint_strings = func_constraints.entry(constraint).or_default();
            
            // Map byte offsets to original indices, then to new indices
            for byte_offset in symbol_byte_offsets {
                if let Some(&orig_idx) = local_offset_to_idx.get(&byte_offset) {
                    if let Some(&new_idx) = local_string_remap.get(&orig_idx) {
                        constraint_strings.insert(new_idx);
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Writes the merged database to the specified output path.
/// 
/// # Arguments
/// 
/// * `output_path` - Path where the merged database will be written
/// * `functions` - The merged function data
/// * `strings` - The merged string table
fn write_merged_database(
    output_path: &Path,
    functions: &BTreeMap<FunctionGuid, HashMap<Constraint, HashSet<u64>>>,
    strings: &Vec<String>,
) -> Result<()> {
    let file = File::create(output_path)?;
    let mut writer = BufWriter::new(file);
    
    let db_writer = DbWriter::new(functions, strings);
    db_writer.write(&mut writer)?;
    
    Ok(())
}

/// Creates a consistent progress bar style for merge operations.
fn progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, {eta}) {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbWriter;
    use crate::warp::ConstraintGuid;
    use std::io::Cursor;
    use tempfile::TempDir;

    // Helper function to create a test database with specific content
    fn create_test_db(
        functions: &BTreeMap<FunctionGuid, HashMap<Constraint, HashSet<u64>>>,
        strings: &Vec<String>,
    ) -> Vec<u8> {
        let writer = DbWriter::new(functions, strings);
        let mut buffer = vec![];
        writer.write(&mut Cursor::new(&mut buffer))
            .expect("Failed to write test database");
        buffer
    }

    // Helper function to write a database to a temporary file
    fn write_db_to_file(dir: &TempDir, name: &str, data: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, data)
            .expect("Failed to write test database file");
        path
    }

    #[test]
    fn test_basic_merge_two_databases() {
        // Create first database
        let func_guid1 = FunctionGuid(0x1111111111111111);
        let constraint1 = Constraint {
            guid: ConstraintGuid(0x2222222222222222),
            offset: Some(100),
        };
        let strings1 = vec!["string1".to_string(), "string2".to_string()];
        let mut constraints1 = HashMap::new();
        constraints1.insert(constraint1, HashSet::from([0, 1]));
        let mut functions1 = BTreeMap::new();
        functions1.insert(func_guid1, constraints1);

        // Create second database
        let func_guid2 = FunctionGuid(0x3333333333333333);
        let constraint2 = Constraint {
            guid: ConstraintGuid(0x4444444444444444),
            offset: Some(200),
        };
        let strings2 = vec!["string3".to_string(), "string4".to_string()];
        let mut constraints2 = HashMap::new();
        constraints2.insert(constraint2, HashSet::from([0, 1]));
        let mut functions2 = BTreeMap::new();
        functions2.insert(func_guid2, constraints2);

        // Write databases to temporary files
        let temp_dir = TempDir::new().unwrap();
        let db1_data = create_test_db(&functions1, &strings1);
        let db2_data = create_test_db(&functions2, &strings2);
        let db1_path = write_db_to_file(&temp_dir, "db1.fold", &db1_data);
        let db2_path = write_db_to_file(&temp_dir, "db2.fold", &db2_data);
        let output_path = temp_dir.path().join("merged.fold");

        // Merge databases
        merge_databases(&[db1_path, db2_path], &output_path)
            .expect("Failed to merge databases");

        // Verify merged database
        let merged_data = std::fs::read(&output_path).unwrap();
        let merged_db = Db::new(&merged_data)
            .expect("Failed to parse merged database");

        // Check function count
        assert_eq!(merged_db.function_count(), 2);

        // Check string count (all 4 strings should be unique)
        assert_eq!(merged_db.string_count(), 4);

        // Verify first function
        let constraints1 = merged_db.query_constraints_for_function(func_guid1).unwrap();
        assert_eq!(constraints1.len(), 1);
        let constraint1_guid = ConstraintGuid(0x2222222222222222);
        assert_eq!(constraints1[&constraint1_guid].len(), 2);

        // Verify second function
        let constraints2 = merged_db.query_constraints_for_function(func_guid2).unwrap();
        assert_eq!(constraints2.len(), 1);
        let constraint2_guid = ConstraintGuid(0x4444444444444444);
        assert_eq!(constraints2[&constraint2_guid].len(), 2);
    }

    #[test]
    fn test_string_deduplication_across_databases() {
        // Create databases with overlapping strings
        let func_guid1 = FunctionGuid(0x1111111111111111);
        let func_guid2 = FunctionGuid(0x2222222222222222);
        let constraint = Constraint {
            guid: ConstraintGuid(0x3333333333333333),
            offset: None,
        };

        // Database 1: ["common", "unique1", "shared"]
        let strings1 = vec![
            "common".to_string(),
            "unique1".to_string(),
            "shared".to_string(),
        ];
        let mut constraints1 = HashMap::new();
        constraints1.insert(constraint, HashSet::from([0, 1, 2]));
        let mut functions1 = BTreeMap::new();
        functions1.insert(func_guid1, constraints1);

        // Database 2: ["shared", "unique2", "common"]
        let strings2 = vec![
            "shared".to_string(),
            "unique2".to_string(),
            "common".to_string(),
        ];
        let mut constraints2 = HashMap::new();
        constraints2.insert(constraint, HashSet::from([0, 1, 2]));
        let mut functions2 = BTreeMap::new();
        functions2.insert(func_guid2, constraints2);

        // Write and merge
        let temp_dir = TempDir::new().unwrap();
        let db1_data = create_test_db(&functions1, &strings1);
        let db2_data = create_test_db(&functions2, &strings2);
        let db1_path = write_db_to_file(&temp_dir, "db1.fold", &db1_data);
        let db2_path = write_db_to_file(&temp_dir, "db2.fold", &db2_data);
        let output_path = temp_dir.path().join("merged.fold");

        merge_databases(&[db1_path, db2_path], &output_path)
            .expect("Failed to merge databases");

        // Verify deduplication
        let merged_data = std::fs::read(&output_path).unwrap();
        let merged_db = Db::new(&merged_data)
            .expect("Failed to parse merged database");

        // Should have 4 unique strings: "common", "unique1", "shared", "unique2"
        assert_eq!(merged_db.string_count(), 4);

        // Verify all strings are present
        let all_strings: HashSet<String> = merged_db.iter_strings().collect();
        assert!(all_strings.contains("common"));
        assert!(all_strings.contains("unique1"));
        assert!(all_strings.contains("shared"));
        assert!(all_strings.contains("unique2"));
    }

    #[test]
    fn test_function_constraint_preservation() {
        // Create a complex function with multiple constraints
        let func_guid = FunctionGuid(0x1111111111111111);
        let constraint1 = Constraint {
            guid: ConstraintGuid(0x2222222222222222),
            offset: Some(100),
        };
        let constraint2 = Constraint {
            guid: ConstraintGuid(0x3333333333333333),
            offset: Some(200),
        };
        let constraint3 = Constraint {
            guid: ConstraintGuid(0x4444444444444444),
            offset: None,
        };

        let strings = vec![
            "symbol1".to_string(),
            "symbol2".to_string(),
            "symbol3".to_string(),
            "symbol4".to_string(),
        ];

        let mut constraints = HashMap::new();
        constraints.insert(constraint1, HashSet::from([0, 1]));
        constraints.insert(constraint2, HashSet::from([1, 2, 3]));
        constraints.insert(constraint3, HashSet::from([0, 3]));

        let mut functions = BTreeMap::new();
        functions.insert(func_guid, constraints.clone());

        // Create two databases with the same function
        let temp_dir = TempDir::new().unwrap();
        let db_data = create_test_db(&functions, &strings);
        let db1_path = write_db_to_file(&temp_dir, "db1.fold", &db_data);
        let db2_path = write_db_to_file(&temp_dir, "db2.fold", &db_data);
        let output_path = temp_dir.path().join("merged.fold");

        merge_databases(&[db1_path, db2_path], &output_path)
            .expect("Failed to merge databases");

        // Verify constraints are preserved
        let merged_data = std::fs::read(&output_path).unwrap();
        let merged_db = Db::new(&merged_data)
            .expect("Failed to parse merged database");

        let merged_constraints = merged_db.query_constraints_for_function(func_guid).unwrap();
        assert_eq!(merged_constraints.len(), 3);

        // Verify each constraint
        assert_eq!(merged_constraints[&ConstraintGuid(0x2222222222222222)].len(), 2);
        assert_eq!(merged_constraints[&ConstraintGuid(0x3333333333333333)].len(), 3);
        assert_eq!(merged_constraints[&ConstraintGuid(0x4444444444444444)].len(), 2);
    }

    #[test]
    fn test_merge_empty_database() {
        // Create one normal database and one empty database
        let func_guid = FunctionGuid(0x1111111111111111);
        let constraint = Constraint {
            guid: ConstraintGuid(0x2222222222222222),
            offset: None,
        };
        let strings = vec!["test".to_string()];
        let mut constraints = HashMap::new();
        constraints.insert(constraint, HashSet::from([0]));
        let mut functions = BTreeMap::new();
        functions.insert(func_guid, constraints);

        let empty_functions = BTreeMap::new();
        let empty_strings = Vec::new();

        let temp_dir = TempDir::new().unwrap();
        let normal_db_data = create_test_db(&functions, &strings);
        let empty_db_data = create_test_db(&empty_functions, &empty_strings);
        let normal_path = write_db_to_file(&temp_dir, "normal.fold", &normal_db_data);
        let empty_path = write_db_to_file(&temp_dir, "empty.fold", &empty_db_data);
        let output_path = temp_dir.path().join("merged.fold");

        // Test merging empty with normal
        merge_databases(&[empty_path.clone(), normal_path.clone()], &output_path).unwrap();

        let merged_data = std::fs::read(&output_path).unwrap();
        let merged_db = Db::new(&merged_data)
            .expect("Failed to parse merged database");

        assert_eq!(merged_db.function_count(), 1);
        assert_eq!(merged_db.string_count(), 1);

        // Test merging normal with empty (opposite order)
        let output_path2 = temp_dir.path().join("merged2.fold");
        merge_databases(&[normal_path, empty_path], &output_path2).unwrap();

        let merged_data2 = std::fs::read(&output_path2).unwrap();
        let merged_db2 = Db::new(&merged_data2).unwrap();

        assert_eq!(merged_db2.function_count(), 1);
        assert_eq!(merged_db2.string_count(), 1);
    }

    #[test]
    fn test_merge_duplicate_functions_combines_constraints() {
        // Create the same function in two databases with different constraints
        let func_guid = FunctionGuid(0x1111111111111111);
        let constraint1 = Constraint {
            guid: ConstraintGuid(0x2222222222222222),
            offset: Some(100),
        };
        let constraint2 = Constraint {
            guid: ConstraintGuid(0x3333333333333333),
            offset: Some(200),
        };

        // Database 1: Function with constraint1
        let strings1 = vec!["symbol1".to_string(), "symbol2".to_string()];
        let mut constraints1 = HashMap::new();
        constraints1.insert(constraint1, HashSet::from([0, 1]));
        let mut functions1 = BTreeMap::new();
        functions1.insert(func_guid, constraints1);

        // Database 2: Same function with constraint2
        let strings2 = vec!["symbol3".to_string(), "symbol4".to_string()];
        let mut constraints2 = HashMap::new();
        constraints2.insert(constraint2, HashSet::from([0, 1]));
        let mut functions2 = BTreeMap::new();
        functions2.insert(func_guid, constraints2);

        let temp_dir = TempDir::new().unwrap();
        let db1_data = create_test_db(&functions1, &strings1);
        let db2_data = create_test_db(&functions2, &strings2);
        let db1_path = write_db_to_file(&temp_dir, "db1.fold", &db1_data);
        let db2_path = write_db_to_file(&temp_dir, "db2.fold", &db2_data);
        let output_path = temp_dir.path().join("merged.fold");

        merge_databases(&[db1_path, db2_path], &output_path)
            .expect("Failed to merge databases");

        // Verify the function has both constraints
        let merged_data = std::fs::read(&output_path).unwrap();
        let merged_db = Db::new(&merged_data)
            .expect("Failed to parse merged database");

        assert_eq!(merged_db.function_count(), 1);
        let merged_constraints = merged_db.query_constraints_for_function(func_guid).unwrap();
        assert_eq!(merged_constraints.len(), 2);
        assert!(merged_constraints.contains_key(&ConstraintGuid(0x2222222222222222)));
        assert!(merged_constraints.contains_key(&ConstraintGuid(0x3333333333333333)));
    }

    #[test]
    fn test_merge_multiple_databases() {
        // Create three databases
        let mut all_functions = BTreeMap::new();
        let mut temp_paths = Vec::new();
        let temp_dir = TempDir::new().unwrap();

        for i in 0..3 {
            let func_guid = FunctionGuid(0x1111111111111111 + i);
            let constraint = Constraint {
                guid: ConstraintGuid(0x2222222222222222 + i),
                offset: Some(100 * (i + 1) as i64),
            };
            let strings = vec![
                format!("string{}_1", i),
                format!("string{}_2", i),
            ];
            let mut constraints = HashMap::new();
            constraints.insert(constraint, HashSet::from([0, 1]));
            let mut functions = BTreeMap::new();
            functions.insert(func_guid, constraints);
            all_functions.insert(func_guid, functions[&func_guid].clone());

            let db_data = create_test_db(&functions, &strings);
            let db_path = write_db_to_file(&temp_dir, &format!("db{}.fold", i), &db_data);
            temp_paths.push(db_path);
        }

        let output_path = temp_dir.path().join("merged.fold");
        merge_databases(&temp_paths, &output_path).unwrap();

        // Verify all functions are present
        let merged_data = std::fs::read(&output_path).unwrap();
        let merged_db = Db::new(&merged_data)
            .expect("Failed to parse merged database");

        assert_eq!(merged_db.function_count(), 3);
        assert_eq!(merged_db.string_count(), 6); // 2 strings per database, all unique

        // Verify each function
        for i in 0..3 {
            let func_guid = FunctionGuid(0x1111111111111111 + i);
            let constraints = merged_db.query_constraints_for_function(func_guid).unwrap();
            assert_eq!(constraints.len(), 1);
        }
    }

    #[test]
    fn test_error_handling_invalid_database_path() {
        let temp_dir = TempDir::new().unwrap();
        let non_existent_path = temp_dir.path().join("non_existent.fold");
        let output_path = temp_dir.path().join("output.fold");

        // With skip-on-error logic, a single invalid database results in an error about needing 2 databases
        let result = merge_databases(&[non_existent_path], &output_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Need at least 2 valid databases"));
    }

    #[test]
    fn test_error_handling_invalid_database_format() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create an invalid database file
        let invalid_data = b"This is not a valid database format";
        let invalid_path = write_db_to_file(&temp_dir, "invalid.fold", invalid_data);
        let output_path = temp_dir.path().join("output.fold");

        let result = merge_databases(&[invalid_path], &output_path);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_output_directory_writability_check() {
        let temp_dir = TempDir::new().unwrap();
        let non_existent_dir = temp_dir.path().join("non_existent_dir");
        let output_path = non_existent_dir.join("output.fold");
        
        // Create dummy databases
        let func_guid = FunctionGuid(0x1111111111111111);
        let constraint = Constraint {
            guid: ConstraintGuid(0x2222222222222222),
            offset: None,
        };
        let strings = vec!["test".to_string()];
        let mut constraints = HashMap::new();
        constraints.insert(constraint, HashSet::from([0]));
        let mut functions = BTreeMap::new();
        functions.insert(func_guid, constraints);
        
        let db_data = create_test_db(&functions, &strings);
        let db1_path = write_db_to_file(&temp_dir, "db1.fold", &db_data);
        let db2_path = write_db_to_file(&temp_dir, "db2.fold", &db_data);
        
        // Try to merge to a non-existent directory
        let result = merge_databases(&[db1_path, db2_path], &output_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Output directory does not exist"));
    }

    #[test]
    fn test_complex_constraint_relationships() {
        // Test merging databases where functions share some constraints but with different symbols
        let func_guid = FunctionGuid(0x1111111111111111);
        let shared_constraint = Constraint {
            guid: ConstraintGuid(0x2222222222222222),
            offset: Some(100),
        };
        let unique_constraint1 = Constraint {
            guid: ConstraintGuid(0x3333333333333333),
            offset: Some(200),
        };
        let unique_constraint2 = Constraint {
            guid: ConstraintGuid(0x4444444444444444),
            offset: None,
        };

        // Database 1: Function with shared_constraint (symbols 0,1) and unique_constraint1 (symbol 2)
        let strings1 = vec![
            "shared_symbol1".to_string(),
            "shared_symbol2".to_string(),
            "unique_symbol1".to_string(),
        ];
        let mut constraints1 = HashMap::new();
        constraints1.insert(shared_constraint, HashSet::from([0, 1]));
        constraints1.insert(unique_constraint1, HashSet::from([2]));
        let mut functions1 = BTreeMap::new();
        functions1.insert(func_guid, constraints1);

        // Database 2: Same function with shared_constraint (symbols 0,1) and unique_constraint2 (symbol 2)
        let strings2 = vec![
            "shared_symbol3".to_string(),
            "shared_symbol4".to_string(),
            "unique_symbol2".to_string(),
        ];
        let mut constraints2 = HashMap::new();
        constraints2.insert(shared_constraint, HashSet::from([0, 1]));
        constraints2.insert(unique_constraint2, HashSet::from([2]));
        let mut functions2 = BTreeMap::new();
        functions2.insert(func_guid, constraints2);

        let temp_dir = TempDir::new().unwrap();
        let db1_data = create_test_db(&functions1, &strings1);
        let db2_data = create_test_db(&functions2, &strings2);
        let db1_path = write_db_to_file(&temp_dir, "db1.fold", &db1_data);
        let db2_path = write_db_to_file(&temp_dir, "db2.fold", &db2_data);
        let output_path = temp_dir.path().join("merged.fold");

        merge_databases(&[db1_path, db2_path], &output_path)
            .expect("Failed to merge databases");

        // Verify merged result
        let merged_data = std::fs::read(&output_path).unwrap();
        let merged_db = Db::new(&merged_data)
            .expect("Failed to parse merged database");

        let merged_constraints = merged_db.query_constraints_for_function(func_guid).unwrap();
        
        // Should have all three constraints
        assert_eq!(merged_constraints.len(), 3);
        
        // Shared constraint should have symbols from both databases
        let shared_symbols = &merged_constraints[&ConstraintGuid(0x2222222222222222)];
        assert_eq!(shared_symbols.len(), 4); // All 4 shared symbols
        
        // Unique constraints should each have 1 symbol
        assert_eq!(merged_constraints[&ConstraintGuid(0x3333333333333333)].len(), 1);
        assert_eq!(merged_constraints[&ConstraintGuid(0x4444444444444444)].len(), 1);
    }

    #[test]
    fn test_large_scale_merge() {
        // Test merging with many functions and strings
        let temp_dir = TempDir::new().unwrap();
        let mut db_paths = Vec::new();

        // Create 5 databases with 100 functions each
        for db_idx in 0..5 {
            let mut functions = BTreeMap::new();
            let mut strings = Vec::new();

            // Create 100 unique strings per database
            for i in 0..100 {
                strings.push(format!("db{}_string{}", db_idx, i));
            }

            // Create 100 functions per database
            for func_idx in 0..100 {
                let func_guid = FunctionGuid((db_idx as u64) << 32 | func_idx);
                let mut constraints = HashMap::new();

                // Each function has 1-3 constraints
                for constraint_idx in 0..((func_idx % 3) + 1) {
                    let constraint = Constraint {
                        guid: ConstraintGuid((func_guid.0 << 8) | constraint_idx as u64),
                        offset: Some(constraint_idx as i64 * 100),
                    };
                    
                    // Each constraint references 1-5 strings
                    let mut symbol_indices = HashSet::new();
                    for i in 0..((constraint_idx % 5) + 1) {
                        symbol_indices.insert((func_idx + i) % 100);
                    }
                    
                    constraints.insert(constraint, symbol_indices);
                }

                functions.insert(func_guid, constraints);
            }

            let db_data = create_test_db(&functions, &strings);
            let db_path = write_db_to_file(&temp_dir, &format!("large_db{}.fold", db_idx), &db_data);
            db_paths.push(db_path);
        }

        let output_path = temp_dir.path().join("large_merged.fold");
        merge_databases(&db_paths, &output_path).unwrap();

        // Verify the merge
        let merged_data = std::fs::read(&output_path).unwrap();
        let merged_db = Db::new(&merged_data)
            .expect("Failed to parse merged database");

        assert_eq!(merged_db.function_count(), 500); // 5 databases * 100 functions
        assert_eq!(merged_db.string_count(), 500); // All strings are unique
    }
}