use crate::warp::{ConstraintGuid, FunctionGuid};
use anyhow::{Result, bail};
use byteorder::{LE, WriteBytesExt};
use std::collections::{BTreeMap, HashMap, HashSet};
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
const VERSION: u8 = 1;

const CONSTRAINTS_SIZE: usize = 16;
const CONSTRAINT_STRINGS_SIZE: usize = 4;
const FUNCTION_CONSTRAINTS_SIZE: usize = 4 + 4 + 4;
const FUNCTION_SIZE: usize = 16 + 4 + 4;

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

    pub fn query_constraints_for_function(
        &self,
        function_guid: &FunctionGuid,
    ) -> Result<HashMap<ConstraintGuid, Vec<&'a str>>> {
        // Find the function in the functions section using binary search
        let functions_start = self.header.functions_offset as usize;
        let num_functions = self.u32_at(functions_start) as usize;

        // Binary search for the function
        let mut left = 0;
        let mut right = num_functions;
        let mut found_function = None;

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
                    found_function = Some((constraint_index, num_constraints));
                    break;
                }
            }
        }

        let (constraint_index, num_constraints) = match found_function {
            Some(f) => f,
            None => return Ok(Default::default()),
        };

        // Read constraints
        let constraints_start = self.header.function_constraints_offset as usize + 4;
        let mut constraints = HashMap::with_capacity(num_constraints);

        // Skip to the right constraint index
        let constraint_offset = constraints_start + (constraint_index * FUNCTION_CONSTRAINTS_SIZE);

        for i in 0..num_constraints {
            let offset = constraint_offset + (i * FUNCTION_CONSTRAINTS_SIZE);
            let constraint_index = self.u32_at(offset) as usize;
            let constraint_guid = ConstraintGuid(
                self.uuid_at(self.header.constraints_offset as usize + 4 + constraint_index * 16),
            );
            let string_count = self.u32_at(offset + 4) as usize;
            let string_index = self.u32_at(offset + 8) as usize;

            let constraint_strings_start = self.header.constraint_strings_offset as usize + 4;
            let mut strings = vec![];
            for j in 0..string_count {
                let offset =
                    constraint_strings_start + (string_index + j) * CONSTRAINT_STRINGS_SIZE;
                let offset = self.u32_at(offset);
                strings.push(self.read_string_at_offset(offset)?);
            }

            constraints.insert(constraint_guid, strings);
        }

        Ok(constraints)
    }

    fn read_string_at_offset(&self, offset: u32) -> Result<&'a str> {
        let file_offset = self.header.strings_offset as usize + offset as usize;
        let len = self.u32_at(file_offset) as usize;
        Ok(str::from_utf8(self.slice_at(file_offset + 4, len))?)
    }
}

pub struct DbWriter<'a> {
    functions: &'a BTreeMap<FunctionGuid, HashMap<ConstraintGuid, HashSet<u64>>>,
    strings: &'a Vec<String>,
}

impl<'a> DbWriter<'a> {
    pub fn new(
        functions: &'a BTreeMap<FunctionGuid, HashMap<ConstraintGuid, HashSet<u64>>>,
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
            for guid in f.keys() {
                constraints_map.entry(guid).or_insert_with(|| {
                    constraints_vec.push(guid);
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
            for (guid, strings) in f {
                writer.write_u32::<LE>(constraints_map[guid])?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read() {
        let func_guid = FunctionGuid(Uuid::from_bytes([b'A'; 16]));
        let constraint1 = ConstraintGuid(Uuid::from_bytes([b'B'; 16]));
        let constraint2 = ConstraintGuid(Uuid::from_bytes([b'C'; 16]));

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

        // Write to a buffer
        let mut buffer = vec![];
        writer
            .write(&mut std::io::Cursor::new(&mut buffer))
            .unwrap();
        std::fs::write("buh.fold", &buffer).unwrap();

        let db = Db::new(&buffer).unwrap();
        let constraints = db.query_constraints_for_function(&func_guid).unwrap();

        assert_eq!(constraints.len(), 2);
        assert_eq!(
            constraints[&constraint1],
            vec!["test_value_1", "test_value_3"]
        );
        assert_eq!(
            constraints[&constraint2],
            vec!["test_value_1", "test_value_2"]
        );
    }
}
