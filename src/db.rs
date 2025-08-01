use crate::warp::{Constraint, ConstraintGuid, FunctionGuid};
use anyhow::{Result, bail};
use byteorder::{LE, WriteBytesExt};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::{self, Seek, SeekFrom, Write};
use uuid::Uuid;

// header
// [8 bytes] magic
// [file offset of strings section]
// [file offset of constraints section]
// [file offset of constraint strings section]
// [file offset of function constraints section]
// [file offset of functions section]
//
// strings section
// [4 bytes] count
// for each:
//   [4 bytes] String length
//   [N bytes] UTF-8 string data
//
// constraints section
// [4 bytes] count
// for each:
//   [16 bytes] ConstraintGUID
//
// constraint strings section
// [4 bytes] count
// for each:
//   [4 bytes] byte offset into strings section
//
// function constraints section
// [4 bytes] count
// for each:
//   [4 bytes] index of constraint
//   [8 bytes] constraint offset (i64::MAX if None)
//   [4 bytes] number of strings
//   [4 bytes] index of constraint strings
//
// functions section
// [4 bytes] count
// for each:
//   [16 bytes] FunctionGUID
//   [4 bytes] index of constraints
//   [4 bytes] number of constraints

const MAGIC: &[u8; 7] = b"BINFOLD";
const VERSION: u8 = 2;

const CONSTRAINTS_SIZE: usize = 16;
const CONSTRAINT_STRINGS_SIZE: usize = 4;
const FUNCTION_CONSTRAINTS_SIZE: usize = 4 + 8 + 4 + 4;
const FUNCTION_SIZE: usize = 16 + 4 + 4;

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
    header: Header,
}

#[derive(Debug)]
pub struct Header {
    pub strings_offset: u64,
    pub constraints_offset: u64,
    pub constraint_strings_offset: u64,
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
            constraint_strings_offset: u64::from_le_bytes(data[24..32].try_into().unwrap()),
            function_constraints_offset: u64::from_le_bytes(data[32..40].try_into().unwrap()),
            functions_offset: u64::from_le_bytes(data[40..48].try_into().unwrap()),
        };

        Ok(Db { data, header })
    }

    fn slice_at(&self, offset: usize, len: usize) -> &'a [u8] {
        &self.data[offset..offset + len]
    }
    fn uuid_at(&self, offset: usize) -> Uuid {
        Uuid::from_bytes(self.slice_at(offset, 16).try_into().unwrap())
    }
    fn u32_at(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.slice_at(offset, 4).try_into().unwrap())
    }
    fn i64_at(&self, offset: usize) -> i64 {
        i64::from_le_bytes(self.slice_at(offset, 8).try_into().unwrap())
    }

    pub fn function_count(&self) -> usize {
        let functions_start = self.header.functions_offset as usize;
        self.u32_at(functions_start) as usize
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
        function_guid: &FunctionGuid,
    ) -> ConstraintIterator<'db, 'a> {
        // Find the function in the functions section using binary search
        let functions_start = self.header.functions_offset as usize;
        let num_functions = self.u32_at(functions_start) as usize;

        // Binary search for the function
        let mut left = 0;
        let mut right = num_functions;

        while left < right {
            let mid = left + (right - left) / 2;
            let function_offset = functions_start + 4 + (mid * FUNCTION_SIZE);

            let current_guid = FunctionGuid(self.uuid_at(function_offset));

            match current_guid.cmp(function_guid) {
                std::cmp::Ordering::Less => left = mid + 1,
                std::cmp::Ordering::Greater => right = mid,
                std::cmp::Ordering::Equal => {
                    let constraint_index = self.u32_at(function_offset + 16) as usize;
                    let num_constraints = self.u32_at(function_offset + 20) as usize;

                    return ConstraintIterator {
                        db: self,
                        constraint_index,
                        current: 0,
                        total: num_constraints,
                    };
                }
            }
        }

        ConstraintIterator {
            db: self,
            constraint_index: 0,
            current: 0,
            total: 0,
        }
    }

    pub fn query_constraints_for_function(
        &self,
        function_guid: &FunctionGuid,
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
        function_guid: &FunctionGuid,
    ) -> HashMap<ConstraintGuid, Vec<StringRef<'a>>> {
        self.iter_constraints(function_guid)
            .map(|c| (c.constraint.guid, c.iter_symbols().collect()))
            .collect()
    }

    fn read_string_at_offset(&self, offset: u32) -> Result<&'a str> {
        let file_offset = self.header.strings_offset as usize + offset as usize;
        let len = self.u32_at(file_offset) as usize;
        Ok(str::from_utf8(self.slice_at(file_offset + 4, len))?)
    }

    fn string_ref_at_offset(&self, offset: u32) -> StringRef<'a> {
        let file_offset = self.header.strings_offset as usize + offset as usize;
        let len = self.u32_at(file_offset) as usize;
        StringRef {
            data: self.slice_at(file_offset + 4, len),
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

        // Write strings section and record offsets as we go
        let strings_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.strings.len().try_into().unwrap())?;

        let mut string_offsets = Vec::with_capacity(self.strings.len());
        let mut offset = 4;
        for string in self.strings {
            string_offsets.push(offset);
            writer.write_u32::<LE>(string.len().try_into().unwrap())?;
            writer.write_all(string.as_bytes())?;
            offset += 4 + string.len() as u32;
        }

        // Write constraints section
        let constraints_offset = writer.stream_position()?;
        let mut constraints_map: HashMap<&ConstraintGuid, u32> = Default::default();
        let mut constraints_vec: Vec<&ConstraintGuid> = Default::default();
        for f in self.functions.values() {
            for constraint in f.keys() {
                constraints_map.entry(&constraint.guid).or_insert_with(|| {
                    constraints_vec.push(&constraint.guid);
                    (constraints_vec.len() - 1).try_into().unwrap()
                });
            }
        }
        writer.write_u32::<LE>(constraints_vec.len().try_into().unwrap())?;
        for guid in constraints_vec {
            writer.write_all(guid.0.as_bytes())?;
        }

        // Write constraint strings section
        let constraint_strings_offset = writer.stream_position()?;
        let all_constraint_strings: usize = self
            .functions
            .values()
            .map(|c| c.values().map(|s| s.len()).sum::<usize>())
            .sum();
        writer.write_u32::<LE>(all_constraint_strings.try_into().unwrap())?;
        let mut constraint_string_indexes = vec![];
        let mut index = 0;
        for f in self.functions.values() {
            for strings in f.values() {
                constraint_string_indexes.push(index);
                for string_idx in strings {
                    writer.write_u32::<LE>(string_offsets[*string_idx as usize])?;
                    index += 1;
                }
            }
        }

        // Write function constraints section
        let function_constraints_offset = writer.stream_position()?;
        let all_constraints: usize = self.functions.values().map(|c| c.len()).sum();
        writer.write_u32::<LE>(all_constraints.try_into().unwrap())?;
        let mut constraint_index = 0;
        for f in self.functions.values() {
            for (constraint, strings) in f {
                writer.write_u32::<LE>(constraints_map[&constraint.guid])?;
                writer.write_i64::<LE>(constraint.offset.unwrap_or(i64::MAX))?;
                writer.write_u32::<LE>(strings.len().try_into().unwrap())?;
                writer.write_u32::<LE>(constraint_string_indexes[constraint_index])?;
                constraint_index += 1;
            }
        }

        // Write functions section
        let functions_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.functions.len().try_into().unwrap())?;
        let mut constraint_index = 0;
        for (func_guid, constraints) in self.functions {
            writer.write_all(func_guid.0.as_bytes())?;
            writer.write_u32::<LE>(constraint_index)?;
            writer.write_u32::<LE>(constraints.len().try_into().unwrap())?;
            constraint_index += constraints.len() as u32;
        }

        // Go back and write the actual offsets
        writer.seek(SeekFrom::Start(8))?;
        writer.write_u64::<LE>(strings_offset)?;
        writer.write_u64::<LE>(constraints_offset)?;
        writer.write_u64::<LE>(constraint_strings_offset)?;
        writer.write_u64::<LE>(function_constraints_offset)?;
        writer.write_u64::<LE>(functions_offset)?;

        Ok(())
    }
}

pub struct ConstraintIterator<'db, 'a> {
    db: &'db Db<'a>,
    constraint_index: usize,
    current: usize,
    total: usize,
}

pub struct ConstraintInfo<'db, 'a> {
    db: &'db Db<'a>,
    constraint: Constraint,
    symbol_count: usize,
    string_index: usize,
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
            string_index: self.string_index,
            current: 0,
            total: self.symbol_count,
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

        let constraints_start = self.db.header.function_constraints_offset as usize + 4;
        let offset = constraints_start
            + ((self.constraint_index + self.current) * FUNCTION_CONSTRAINTS_SIZE);

        let constraint_index = self.db.u32_at(offset) as usize;
        let constraint_guid = ConstraintGuid(self.db.uuid_at(
            self.db.header.constraints_offset as usize + 4 + constraint_index * CONSTRAINTS_SIZE,
        ));
        let constraint_offset_raw = self.db.i64_at(offset + 4);
        let constraint_offset = if constraint_offset_raw == i64::MAX {
            None
        } else {
            Some(constraint_offset_raw)
        };
        let string_count = self.db.u32_at(offset + 12) as usize;
        let string_index = self.db.u32_at(offset + 16) as usize;

        self.current += 1;

        Some(ConstraintInfo {
            constraint: Constraint {
                guid: constraint_guid,
                offset: constraint_offset,
            },
            symbol_count: string_count,
            string_index,
            db: self.db,
        })
    }
}

pub struct SymbolIterator<'db, 'a> {
    db: &'db Db<'a>,
    string_index: usize,
    current: usize,
    total: usize,
}

impl<'db, 'a> Iterator for SymbolIterator<'db, 'a> {
    type Item = StringRef<'a>;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.current;
        (remaining, Some(remaining))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.total {
            return None;
        }

        let constraint_strings_start = self.db.header.constraint_strings_offset as usize + 4;
        let offset =
            constraint_strings_start + (self.string_index + self.current) * CONSTRAINT_STRINGS_SIZE;
        let string_offset = self.db.u32_at(offset);

        self.current += 1;
        Some(self.db.string_ref_at_offset(string_offset))
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
        let function_offset = functions_start + 4 + (self.current * FUNCTION_SIZE);

        let func_guid = FunctionGuid(self.db.uuid_at(function_offset));
        self.current += 1;

        Some(func_guid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Vec<u8> {
        let func_guid = FunctionGuid(Uuid::from_bytes([b'A'; 16]));
        let constraint1 = Constraint {
            guid: ConstraintGuid(Uuid::from_bytes([b'B'; 16])),
            offset: Some(100),
        };
        let constraint2 = Constraint {
            guid: ConstraintGuid(Uuid::from_bytes([b'C'; 16])),
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
        let func_guid = FunctionGuid(Uuid::from_bytes([b'A'; 16]));
        let constraint1 = ConstraintGuid(Uuid::from_bytes([b'B'; 16]));
        let constraint2 = ConstraintGuid(Uuid::from_bytes([b'C'; 16]));

        let buffer = test_db();

        let db = Db::new(&buffer).unwrap();
        let constraints = db.query_constraints_for_function(&func_guid).unwrap();

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
        let func_guid1 = FunctionGuid(Uuid::from_bytes([b'A'; 16]));
        let func_guid2 = FunctionGuid(Uuid::from_bytes([b'D'; 16]));

        let buffer = test_db();

        let db = Db::new(&buffer).unwrap();

        // Test direct constraint iterator lookup
        let constraints: Vec<_> = db.iter_constraints(&func_guid1).collect();
        assert_eq!(constraints.len(), 2);

        // Find constraints by their GUIDs
        let constraint1_guid = ConstraintGuid(Uuid::from_bytes([b'B'; 16]));
        let constraint2_guid = ConstraintGuid(Uuid::from_bytes([b'C'; 16]));

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
        assert_eq!(0, db.iter_constraints(&func_guid2).count());
    }
}
