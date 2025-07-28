use crate::warp::{ConstraintGuid, FunctionGuid};
use anyhow::{Result, bail};
use byteorder::{LE, WriteBytesExt};
use std::collections::BTreeMap;
use std::io::{self, Seek, SeekFrom, Write};
use uuid::Uuid;

const MAGIC: &[u8; 8] = b"WARPBIN\0";

const CONSTRAINT_SIZE: usize = 16 + 4;
const FUNCTION_SIZE: usize = 16 + 4 + 4;

pub struct BinaryDatabase<'a> {
    data: &'a [u8],
    header: Header,
}

#[derive(Debug)]
pub struct Header {
    pub strings_offset: u64,
    pub constraints_offset: u64,
    pub functions_offset: u64,
}

impl<'a> BinaryDatabase<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        // Verify magic
        if data.len() < 32 {
            bail!("File too small");
        }
        if &data[0..8] != MAGIC {
            bail!("Invalid magic");
        }

        let header = Header {
            strings_offset: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            constraints_offset: u64::from_le_bytes(data[16..24].try_into().unwrap()),
            functions_offset: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        };

        Ok(BinaryDatabase { data, header })
    }

    fn slice_at(&self, offset: usize, len: usize) -> &[u8] {
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
    ) -> Result<Vec<(ConstraintGuid, &str)>> {
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
            None => return Ok(vec![]),
        };

        // Read constraints
        let constraints_start = self.header.constraints_offset as usize + 4;
        let mut constraints = Vec::with_capacity(num_constraints);

        // Skip to the right constraint index
        let constraint_offset = constraints_start + (constraint_index * CONSTRAINT_SIZE);

        for i in 0..num_constraints {
            let offset = constraint_offset + (i * CONSTRAINT_SIZE);
            let constraint_guid = ConstraintGuid(self.uuid_at(offset));
            let string_offset = self.u32_at(offset + 16);

            // Read the string
            let string = self.read_string_at_offset(string_offset)?;
            constraints.push((constraint_guid, string));
        }

        Ok(constraints)
    }

    fn read_string_at_offset(&self, offset: u32) -> Result<&str> {
        let file_offset = self.header.strings_offset as usize + offset as usize;
        let len = self.u32_at(file_offset) as usize;
        Ok(str::from_utf8(self.slice_at(file_offset + 4, len))?)
    }
}

pub struct BinaryDatabaseWriter<'a> {
    functions: &'a BTreeMap<FunctionGuid, BTreeMap<ConstraintGuid, u64>>,
    strings: &'a Vec<String>,
}

impl<'a> BinaryDatabaseWriter<'a> {
    pub fn new(
        functions: &'a BTreeMap<FunctionGuid, BTreeMap<ConstraintGuid, u64>>,
        strings: &'a Vec<String>,
    ) -> Self {
        BinaryDatabaseWriter { functions, strings }
    }

    pub fn write<W: Write + Seek>(&self, writer: &mut W) -> io::Result<()> {
        // Write header with placeholder offsets
        writer.write_all(MAGIC)?;
        writer.write_u64::<LE>(0)?; // strings_offset placeholder
        writer.write_u64::<LE>(0)?; // constraints_offset placeholder
        writer.write_u64::<LE>(0)?; // functions_offset placeholder

        // Write strings section and record offsets as we go
        let strings_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.strings.len() as u32)?;

        let mut string_offsets = Vec::with_capacity(self.strings.len());
        let mut offset = 4;
        for string in self.strings {
            string_offsets.push(offset);
            writer.write_u32::<LE>(string.len() as u32)?;
            writer.write_all(string.as_bytes())?;
            offset += 4 + string.len() as u32;
        }

        // Collect all constraints in order
        let mut all_constraints = Vec::new();
        for constraints in self.functions.values() {
            for (constraint_guid, string_idx) in constraints {
                all_constraints.push((constraint_guid, *string_idx as usize));
            }
        }

        // Write constraints section
        let constraints_offset = writer.stream_position()?;
        writer.write_u32::<LE>(all_constraints.len() as u32)?;
        for (guid, string_idx) in &all_constraints {
            writer.write_all(guid.0.as_bytes())?;
            writer.write_u32::<LE>(string_offsets[*string_idx])?;
        }

        // Write functions section
        let functions_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.functions.len() as u32)?;

        let mut constraint_index = 0;
        for (func_guid, constraints) in self.functions {
            writer.write_all(func_guid.0.as_bytes())?;
            writer.write_u32::<LE>(constraint_index)?;
            writer.write_u32::<LE>(constraints.len() as u32)?;
            constraint_index += constraints.len() as u32;
        }

        // Go back and write the actual offsets
        writer.seek(SeekFrom::Start(8))?;
        writer.write_u64::<LE>(strings_offset)?;
        writer.write_u64::<LE>(constraints_offset)?;
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

        let strings = vec!["test_value_1".to_string(), "test_value_2".to_string()];

        let mut constraints = BTreeMap::new();
        constraints.insert(constraint1, 0u64); // index 0 in strings
        constraints.insert(constraint2, 1u64); // index 1 in strings

        let mut functions = BTreeMap::new();
        functions.insert(func_guid, constraints);

        let writer = BinaryDatabaseWriter::new(&functions, &strings);

        // Write to a buffer
        let mut buffer = vec![];
        writer
            .write(&mut std::io::Cursor::new(&mut buffer))
            .unwrap();
        std::fs::write("bun.bin", &buffer).unwrap();

        let db = BinaryDatabase::new(&buffer).unwrap();
        let constraints = dbg!(db.query_constraints_for_function(&func_guid).unwrap());

        assert_eq!(constraints.len(), 2);
        assert_eq!(constraints[0].0, constraint1);
        assert_eq!(constraints[0].1, "test_value_1");
        assert_eq!(constraints[1].0, constraint2);
        assert_eq!(constraints[1].1, "test_value_2");
    }
}
