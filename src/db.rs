use crate::warp::{Constraint, ConstraintGuid, FunctionGuid};
use anyhow::{Result, bail};
use byteorder::{LE, WriteBytesExt};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::{self, Seek, SeekFrom, Write};
use varint_rs::{VarintReader, VarintWriter};

// header (fixed size: 48 bytes)
// [ 7 bytes] magic: "BINFOLD"
// [ 1 byte ] version
// [ 8 bytes] file offset of strings section
// [ 8 bytes] file offset of constraints section
// [ 8 bytes] reserved (was constraint strings offset)
// [ 8 bytes] file offset of function constraints section
// [ 8 bytes] file offset of functions section
//
// strings section (variable width)
// [varint] count
// for each:
//   [varint] string length
//   [ N bytes] UTF-8 string data
//
// constraints section (fixed width)
// [ 4 bytes] count (COUNT_FIELD_SIZE)
// for each:
//   [8 bytes] ConstraintGUID (u64)
//
// function constraints section (variable width)
// [ 4 bytes] count (COUNT_FIELD_SIZE)
// for each function:
//   [varint] number of constraints for this function
//   [varint] number of unique string refs for this function
//   for each unique string ref:
//     [varint] byte offset into strings section
//   for each constraint:
//     [varint] index of constraint in constraints section
//     [varint] constraint offset (i64::MAX if None)
//     [varint] number of strings
//     for each string:
//       [varint] index into this function's string ref table
//
// functions section (fixed width for binary search)
// [ 4 bytes] count (COUNT_FIELD_SIZE)
// for each:
//   [8 bytes] FunctionGUID (u64)
//   [ 4 bytes] byte offset to first constraint in function constraints section

const MAGIC: &[u8; 7] = b"BINFOLD";
const VERSION: u8 = 5;

/// Size of count fields in the database format (4 bytes for u32)
const COUNT_FIELD_SIZE: usize = 4;
const CONSTRAINTS_SIZE: usize = 8;
const FUNCTION_SIZE: usize = 8 + COUNT_FIELD_SIZE;

fn write_varint_u64<W: Write>(writer: &mut W, value: u64) -> io::Result<usize> {
    let mut buf = Vec::with_capacity(9);
    buf.write_u64_varint(value)?;
    writer.write_all(&buf)?;
    Ok(buf.len())
}
fn write_varint_i64<W: Write>(writer: &mut W, value: i64) -> io::Result<usize> {
    let mut buf = Vec::with_capacity(9);
    buf.write_i64_varint(value)?;
    writer.write_all(&buf)?;
    Ok(buf.len())
}

/// A reference to a string in the database that can be compared without loading the actual string
#[derive(Clone, Copy)]
pub struct StringRef<'a> {
    data: &'a [u8],
}

impl std::fmt::Debug for StringRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        String::from_utf8_lossy(self.data).fmt(f)
    }
}

impl<'a> StringRef<'a> {
    pub fn as_str(&self) -> Result<&'a str> {
        Ok(std::str::from_utf8(self.data)?)
    }
}

impl<'a> PartialEq for StringRef<'a> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.data.as_ptr(), other.data.as_ptr())
    }
}

impl<'a> Eq for StringRef<'a> {}

impl<'a> Hash for StringRef<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.data.as_ptr()).hash(state);
    }
}

pub struct Db<'a> {
    data: &'a [u8],
    pub header: Header,
}

#[derive(Debug)]
pub struct SectionSizes {
    pub header_size: usize,
    pub strings_size: usize,
    pub constraints_size: usize,
    pub constraint_strings_size: usize,
    pub function_constraints_size: usize,
    pub functions_size: usize,
}

#[derive(Debug)]
pub struct Header {
    pub strings_offset: u64,
    pub constraints_offset: u64,
    pub reserved: u64, // Was constraint_strings_offset in v4
    pub function_constraints_offset: u64,
    pub functions_offset: u64,
}

impl<'a> Db<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < 32 {
            bail!("File too small");
        }
        if &data[0..7] != MAGIC {
            bail!("Invalid magic");
        }
        let version = data[7];
        if version < VERSION {
            bail!("Database version {version} too old");
        }
        if version > VERSION {
            bail!("Database version {version} too new");
        }

        let header = Header {
            strings_offset: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            constraints_offset: u64::from_le_bytes(data[16..24].try_into().unwrap()),
            reserved: u64::from_le_bytes(data[24..32].try_into().unwrap()),
            function_constraints_offset: u64::from_le_bytes(data[32..40].try_into().unwrap()),
            functions_offset: u64::from_le_bytes(data[40..48].try_into().unwrap()),
        };

        Ok(Db { data, header })
    }

    fn slice_at(&self, offset: usize, len: usize) -> &'a [u8] {
        &self.data[offset..offset + len]
    }
    fn u64_at(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.slice_at(offset, 8).try_into().unwrap())
    }
    fn u32_at(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.slice_at(offset, COUNT_FIELD_SIZE).try_into().unwrap())
    }

    fn read_varint_u64_at(&self, offset: usize) -> Result<(u64, usize)> {
        let mut cursor = std::io::Cursor::new(&self.data[offset..]);
        let value = cursor.read_u64_varint()?;
        let bytes_read = cursor.position() as usize;
        Ok((value, bytes_read))
    }

    pub fn function_count(&self) -> usize {
        let functions_start = self.header.functions_offset as usize;
        self.u32_at(functions_start) as usize
    }

    pub fn constraint_count(&self) -> usize {
        let constraints_start = self.header.constraints_offset as usize;
        self.u32_at(constraints_start) as usize
    }

    pub fn string_count(&self) -> usize {
        let strings_start = self.header.strings_offset as usize;
        self.u32_at(strings_start) as usize
    }

    pub fn function_constraints_count(&self) -> usize {
        let function_constraints_start = self.header.function_constraints_offset as usize;
        self.u32_at(function_constraints_start) as usize
    }

    pub fn calculate_section_sizes(&self) -> SectionSizes {
        // Header size is fixed at 48 bytes
        let header_size = 48;

        // Strings section
        let strings_size = (self.header.constraints_offset - self.header.strings_offset) as usize;

        // Constraints section
        let constraints_size =
            (self.header.function_constraints_offset - self.header.constraints_offset) as usize;

        // Constraint strings section is removed in v5
        let constraint_strings_size = 0;

        // Function constraints section
        let function_constraints_size =
            (self.header.functions_offset - self.header.function_constraints_offset) as usize;

        // Functions section (to end of file)
        let functions_size = self.data.len() - self.header.functions_offset as usize;

        SectionSizes {
            header_size,
            strings_size,
            constraints_size,
            constraint_strings_size,
            function_constraints_size,
            functions_size,
        }
    }

    pub fn iter_functions<'db>(&'db self) -> FunctionIterator<'db, 'a> {
        FunctionIterator {
            db: self,
            current: 0,
            total: self.function_count(),
        }
    }

    pub fn iter_constraints<'db>(
        &'db self,
        function_guid: FunctionGuid,
    ) -> ConstraintIterator<'db, 'a> {
        // Find the function in the functions section using binary search
        let functions_start = self.header.functions_offset as usize;
        let num_functions = self.u32_at(functions_start) as usize;

        // Binary search for the function
        let mut left = 0;
        let mut right = num_functions;

        while left < right {
            let mid = left + (right - left) / 2;
            let function_offset = functions_start + COUNT_FIELD_SIZE + (mid * FUNCTION_SIZE);

            let current_guid = FunctionGuid(self.u64_at(function_offset));

            match current_guid.cmp(&function_guid) {
                std::cmp::Ordering::Less => left = mid + 1,
                std::cmp::Ordering::Greater => right = mid,
                std::cmp::Ordering::Equal => {
                    let constraint_byte_offset = self.u32_at(function_offset + 8) as usize;

                    // Read the constraint count and string ref table at the beginning of this function's constraints
                    let offset =
                        self.header.function_constraints_offset as usize + constraint_byte_offset;
                    let mut cursor = std::io::Cursor::new(&self.data[offset..]);

                    let num_constraints = cursor.read_u64_varint().unwrap() as usize;
                    let string_ref_count = cursor.read_u64_varint().unwrap() as usize;
                    let mut string_ref_table = Vec::with_capacity(string_ref_count);

                    for _ in 0..string_ref_count {
                        string_ref_table.push(cursor.read_u64_varint().unwrap());
                    }

                    let table_bytes_read = cursor.position() as usize;

                    return ConstraintIterator {
                        db: self,
                        current_byte_offset: constraint_byte_offset + table_bytes_read,
                        current: 0,
                        total: num_constraints,
                        string_ref_table,
                    };
                }
            }
        }

        ConstraintIterator {
            db: self,
            current_byte_offset: 0,
            current: 0,
            total: 0,
            string_ref_table: Vec::new(),
        }
    }

    pub fn query_constraints_for_function(
        &self,
        function_guid: FunctionGuid,
    ) -> Result<HashMap<ConstraintGuid, Vec<&'a str>>> {
        self.iter_constraints(function_guid)
            .map(|c| {
                c.iter_symbols()
                    .map(|s| s.as_str())
                    .collect::<Result<_>>()
                    .map(|s| (c.constraint.guid, s))
            })
            .collect()
    }

    pub fn query_constraints_for_function_refs(
        &self,
        function_guid: FunctionGuid,
    ) -> HashMap<ConstraintGuid, Vec<StringRef<'a>>> {
        self.iter_constraints(function_guid)
            .map(|c| (c.constraint.guid, c.iter_symbols().collect()))
            .collect()
    }

    fn string_ref_at_offset(&self, offset: usize) -> StringRef<'a> {
        let start = self.header.strings_offset as usize + offset;

        let (len, bytes_read) = self.read_varint_u64_at(start).unwrap();
        StringRef {
            data: self.slice_at(start + bytes_read, len as usize),
        }
    }
}

pub struct DbWriter<'a> {
    functions: &'a BTreeMap<FunctionGuid, HashMap<Constraint, HashSet<u64>>>,
    strings: &'a Vec<String>,
}

impl<'a> DbWriter<'a> {
    pub fn new(
        functions: &'a BTreeMap<FunctionGuid, HashMap<Constraint, HashSet<u64>>>,
        strings: &'a Vec<String>,
    ) -> Self {
        DbWriter { functions, strings }
    }

    pub fn write<W: Write + Seek>(&self, writer: &mut W) -> io::Result<()> {
        // Write header with placeholder offsets
        writer.write_all(MAGIC)?;
        writer.write_u8(VERSION)?;
        writer.write_u64::<LE>(0)?; // strings_offset placeholder
        writer.write_u64::<LE>(0)?; // constraints_offset placeholder
        writer.write_u64::<LE>(0)?; // constraint_strings_offset placeholder
        writer.write_u64::<LE>(0)?; // function_constraints_offset placeholder
        writer.write_u64::<LE>(0)?; // functions_offset placeholder

        // Sort strings for better compression
        let mut sorted_strings: Vec<(usize, &String)> = self.strings.iter().enumerate().collect();
        sorted_strings.sort_by(|a, b| a.1.cmp(b.1));

        // Create mapping from old indices to new indices
        let mut old_to_new_index: Vec<u64> = vec![0; self.strings.len()];
        for (new_idx, (old_idx, _)) in sorted_strings.iter().enumerate() {
            old_to_new_index[*old_idx] = new_idx as u64;
        }

        // Write strings section with varints
        let strings_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.strings.len().try_into().unwrap())?;

        let mut string_byte_offsets_sorted = Vec::with_capacity(self.strings.len());
        let mut byte_offset = 4u64;

        for (_, string) in &sorted_strings {
            string_byte_offsets_sorted.push(byte_offset);
            let len_bytes = write_varint_u64(writer, string.len() as u64)?;
            writer.write_all(string.as_bytes())?;
            byte_offset += len_bytes as u64 + string.len() as u64;
        }

        // Create a mapping from original index to byte offset
        let mut string_byte_offsets = vec![0u64; self.strings.len()];
        for (new_idx, (old_idx, _)) in sorted_strings.iter().enumerate() {
            string_byte_offsets[*old_idx] = string_byte_offsets_sorted[new_idx];
        }

        // Write constraints section
        let constraints_offset = writer.stream_position()?;
        let mut constraints_map: HashMap<ConstraintGuid, u64> = Default::default();
        let mut constraints_vec: Vec<ConstraintGuid> = Default::default();
        for f in self.functions.values() {
            for constraint in f.keys() {
                constraints_map.entry(constraint.guid).or_insert_with(|| {
                    constraints_vec.push(constraint.guid);
                    (constraints_vec.len() - 1).try_into().unwrap()
                });
            }
        }
        writer.write_u32::<LE>(constraints_vec.len().try_into().unwrap())?;
        for guid in constraints_vec {
            writer.write_u64::<LE>(guid.0)?;
        }

        // Skip constraint strings section (reserved space in header)
        let _reserved_offset = writer.stream_position()?;

        // Write function constraints section with varints
        let function_constraints_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.functions.len().try_into().unwrap())?;

        let mut function_constraint_byte_offsets = Vec::with_capacity(self.functions.len());
        let mut current_byte_offset = 4u64;

        for constraints in self.functions.values() {
            function_constraint_byte_offsets.push(current_byte_offset);

            // Write constraint count for this function
            current_byte_offset += write_varint_u64(writer, constraints.len() as u64)? as u64;

            // Build unique string ref table for this function
            let mut unique_string_refs: Vec<u64> = Vec::new();
            let mut string_ref_to_index: HashMap<u64, u64> = HashMap::new();

            for strings in constraints.values() {
                for string_idx in strings {
                    let string_offset = string_byte_offsets[*string_idx as usize];
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        string_ref_to_index.entry(string_offset)
                    {
                        e.insert(unique_string_refs.len() as u64);
                        unique_string_refs.push(string_offset);
                    }
                }
            }

            // Write string ref table
            current_byte_offset +=
                write_varint_u64(writer, unique_string_refs.len() as u64)? as u64;
            for string_ref in &unique_string_refs {
                current_byte_offset += write_varint_u64(writer, *string_ref)? as u64;
            }

            // Write constraints with indices into string ref table
            for (constraint, strings) in constraints {
                current_byte_offset +=
                    write_varint_u64(writer, constraints_map[&constraint.guid])? as u64;
                current_byte_offset +=
                    write_varint_i64(writer, constraint.offset.unwrap_or(i64::MAX))? as u64;
                current_byte_offset += write_varint_u64(writer, strings.len() as u64)? as u64;

                // Write indices into string ref table
                for string_idx in strings {
                    let string_offset = string_byte_offsets[*string_idx as usize];
                    let table_index = string_ref_to_index[&string_offset];
                    current_byte_offset += write_varint_u64(writer, table_index)? as u64;
                }
            }
        }

        // Write functions section (fixed width for binary search)
        let functions_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.functions.len().try_into().unwrap())?;

        for ((func_guid, _), byte_offset) in
            self.functions.iter().zip(function_constraint_byte_offsets)
        {
            writer.write_u64::<LE>(func_guid.0)?;
            writer.write_u32::<LE>(byte_offset.try_into().unwrap())?;
        }

        // Go back and write the actual offsets
        writer.seek(SeekFrom::Start(8))?;
        writer.write_u64::<LE>(strings_offset)?;
        writer.write_u64::<LE>(constraints_offset)?;
        writer.write_u64::<LE>(0)?; // Reserved (was constraint_strings_offset)
        writer.write_u64::<LE>(function_constraints_offset)?;
        writer.write_u64::<LE>(functions_offset)?;

        Ok(())
    }
}

pub struct ConstraintIterator<'db, 'a> {
    db: &'db Db<'a>,
    current_byte_offset: usize,
    current: usize,
    total: usize,
    string_ref_table: Vec<u64>,
}

pub struct ConstraintInfo<'db, 'a> {
    db: &'db Db<'a>,
    constraint: Constraint,
    symbol_count: usize,
    symbol_byte_offsets: Vec<u64>,
}

impl<'db, 'a> ConstraintInfo<'db, 'a> {
    pub fn constraint(&self) -> &Constraint {
        &self.constraint
    }
    pub fn symbol_count(&self) -> usize {
        self.symbol_count
    }

    pub fn iter_symbols(&self) -> SymbolIterator<'db, 'a> {
        SymbolIterator {
            db: self.db,
            symbol_byte_offsets: self.symbol_byte_offsets.clone(),
            current: 0,
        }
    }
}

impl<'db, 'a> Iterator for ConstraintIterator<'db, 'a> {
    type Item = ConstraintInfo<'db, 'a>;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.current;
        (remaining, Some(remaining))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.total {
            return None;
        }

        let offset = self.db.header.function_constraints_offset as usize + self.current_byte_offset;
        let mut cursor = std::io::Cursor::new(&self.db.data[offset..]);

        let constraint_index = cursor.read_u64_varint().unwrap();
        let constraint_offset_raw = cursor.read_i64_varint().unwrap();
        let constraint_offset =
            (constraint_offset_raw != i64::MAX).then_some(constraint_offset_raw);
        let string_count = cursor.read_u64_varint().unwrap() as usize;

        // Read indices into string ref table
        let mut symbol_byte_offsets = Vec::with_capacity(string_count);
        for _ in 0..string_count {
            let table_index = cursor.read_u64_varint().unwrap() as usize;
            symbol_byte_offsets.push(self.string_ref_table[table_index]);
        }

        // Calculate constraint GUID from byte offset
        let constraints_start = self.db.header.constraints_offset as usize;
        let constraint_guid = ConstraintGuid(
            self.db
                .u64_at(constraints_start + 4 + constraint_index as usize * CONSTRAINTS_SIZE),
        );

        self.current += 1;
        self.current_byte_offset += cursor.position() as usize;

        Some(ConstraintInfo {
            constraint: Constraint {
                guid: constraint_guid,
                offset: constraint_offset,
            },
            symbol_count: string_count,
            symbol_byte_offsets,
            db: self.db,
        })
    }
}

pub struct SymbolIterator<'db, 'a> {
    db: &'db Db<'a>,
    symbol_byte_offsets: Vec<u64>,
    current: usize,
}

impl<'db, 'a> Iterator for SymbolIterator<'db, 'a> {
    type Item = StringRef<'a>;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.symbol_byte_offsets.len() - self.current;
        (remaining, Some(remaining))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.symbol_byte_offsets.len() {
            return None;
        }

        let string_byte_offset = self.symbol_byte_offsets[self.current];
        self.current += 1;
        Some(self.db.string_ref_at_offset(string_byte_offset as usize))
    }
}

pub struct FunctionIterator<'db, 'a> {
    db: &'db Db<'a>,
    current: usize,
    total: usize,
}

impl<'db, 'a> Iterator for FunctionIterator<'db, 'a> {
    type Item = FunctionGuid;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.current;
        (remaining, Some(remaining))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.total {
            return None;
        }

        let functions_start = self.db.header.functions_offset as usize;
        let function_offset = functions_start + COUNT_FIELD_SIZE + (self.current * FUNCTION_SIZE);

        let func_guid = FunctionGuid(self.db.u64_at(function_offset));
        self.current += 1;

        Some(func_guid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Vec<u8> {
        let func_guid = FunctionGuid(0x4141414141414141);
        let constraint1 = Constraint {
            guid: ConstraintGuid(0x4242424242424242),
            offset: Some(100),
        };
        let constraint2 = Constraint {
            guid: ConstraintGuid(0x4343434343434343),
            offset: None,
        };

        let strings = vec![
            "test_value_1".to_string(),
            "test_value_2".to_string(),
            "test_value_3".to_string(),
        ];

        let mut constraints = HashMap::new();
        constraints.insert(constraint1, HashSet::from([0, 2]));
        constraints.insert(constraint2, HashSet::from([0, 1]));

        let mut functions = BTreeMap::new();
        functions.insert(func_guid, constraints);

        let writer = DbWriter::new(&functions, &strings);

        let mut buffer = vec![];
        writer
            .write(&mut std::io::Cursor::new(&mut buffer))
            .unwrap();
        buffer
    }

    #[test]
    fn test_write_and_read() {
        let func_guid = FunctionGuid(0x4141414141414141);
        let constraint1 = ConstraintGuid(0x4242424242424242);
        let constraint2 = ConstraintGuid(0x4343434343434343);

        let buffer = test_db();

        let db = Db::new(&buffer).unwrap();
        let constraints = db.query_constraints_for_function(func_guid).unwrap();

        use std::collections::HashSet;

        assert_eq!(constraints.len(), 2);
        assert_eq!(
            HashSet::<&&str>::from_iter(constraints[&constraint1].iter()),
            HashSet::from_iter(["test_value_1", "test_value_3"].iter())
        );
        assert_eq!(
            HashSet::<&&str>::from_iter(constraints[&constraint2].iter()),
            HashSet::from_iter(["test_value_1", "test_value_2"].iter())
        );
    }

    #[test]
    fn test_direct_constraint_iterator() {
        let func_guid1 = FunctionGuid(0x4141414141414141);
        let func_guid2 = FunctionGuid(0x4444444444444444);

        let buffer = test_db();

        let db = Db::new(&buffer).unwrap();

        // Test direct constraint iterator lookup
        let constraints: Vec<_> = db.iter_constraints(func_guid1).collect();
        assert_eq!(constraints.len(), 2);

        // Find constraints by their GUIDs
        let constraint1_guid = ConstraintGuid(0x4242424242424242);
        let constraint2_guid = ConstraintGuid(0x4343434343434343);

        let c1 = constraints
            .iter()
            .find(|c| c.constraint.guid == constraint1_guid)
            .unwrap();
        assert_eq!(c1.symbol_count, 2);
        assert_eq!(c1.constraint.offset, Some(100));

        let c2 = constraints
            .iter()
            .find(|c| c.constraint.guid == constraint2_guid)
            .unwrap();
        assert_eq!(c2.symbol_count, 2);
        assert_eq!(c2.constraint.offset, None);

        // Test non-existent function
        assert_eq!(0, db.iter_constraints(func_guid2).count());
    }
}
