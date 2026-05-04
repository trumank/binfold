use crate::hash::{HashAlgo, XxHash64};
use anyhow::{Result, bail};
use byteorder::{LE, WriteBytesExt};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::{self, Seek, SeekFrom, Write};

/// Hash algorithm pinned for the on-disk DB format.
pub type DbHash = XxHash64;
pub type FunctionGuid = crate::hash::FunctionGuid<DbHash>;
pub type BasicBlockGuid = crate::hash::BasicBlockGuid<DbHash>;
pub type SymbolGuid = crate::hash::SymbolGuid<DbHash>;
pub type ConstraintGuid = crate::hash::ConstraintGuid<DbHash>;

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
//   [8 bytes] ConstraintGUID
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
//   [8 bytes] FunctionGUID
//   [4 bytes] index of constraints
//   [4 bytes] number of constraints

const MAGIC: &[u8; 7] = b"BINFOLD";
const VERSION: u8 = 2;

const DIGEST_SIZE: usize = <DbHash as HashAlgo>::DIGEST_SIZE;
const CONSTRAINTS_SIZE: usize = DIGEST_SIZE;
const CONSTRAINT_STRINGS_SIZE: usize = 4;
const FUNCTION_CONSTRAINTS_SIZE: usize = 4 + 4 + 4;
const FUNCTION_SIZE: usize = DIGEST_SIZE + 4 + 4;

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

struct DataView<'a> {
    data: &'a [u8],
}

impl<'a> DataView<'a> {
    fn slice_at(&self, offset: usize, len: usize) -> &'a [u8] {
        &self.data[offset..offset + len]
    }
    fn u32_at(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.slice_at(offset, 4).try_into().unwrap())
    }
    fn u64_at(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.slice_at(offset, 8).try_into().unwrap())
    }
    fn digest_at<H: HashAlgo>(&self, offset: usize) -> H::Digest {
        H::digest_from_bytes(self.slice_at(offset, H::DIGEST_SIZE))
    }
}

pub struct Db<'a> {
    view: DataView<'a>,
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
        let view = DataView { data };
        if view.slice_at(0, 7) != MAGIC {
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
            strings_offset: view.u64_at(8),
            constraints_offset: view.u64_at(16),
            constraint_strings_offset: view.u64_at(24),
            function_constraints_offset: view.u64_at(32),
            functions_offset: view.u64_at(40),
        };

        Ok(Db { view, header })
    }

    pub fn function_count(&self) -> usize {
        let functions_start = self.header.functions_offset as usize;
        self.view.u32_at(functions_start) as usize
    }

    pub fn strings_count(&self) -> usize {
        let strings_start = self.header.strings_offset as usize;
        self.view.u32_at(strings_start) as usize
    }

    pub fn constraints_count(&self) -> usize {
        let constraints_start = self.header.constraints_offset as usize;
        self.view.u32_at(constraints_start) as usize
    }

    /// Total number of symbol references across all constraints (not unique strings)
    pub fn symbol_references_count(&self) -> usize {
        let constraint_strings_start = self.header.constraint_strings_offset as usize;
        self.view.u32_at(constraint_strings_start) as usize
    }

    pub fn function_constraints_count(&self) -> usize {
        let function_constraints_start = self.header.function_constraints_offset as usize;
        self.view.u32_at(function_constraints_start) as usize
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn data_len(&self) -> usize {
        self.view.data.len()
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
        let num_functions = self.view.u32_at(functions_start) as usize;

        // Binary search for the function
        let mut left = 0;
        let mut right = num_functions;

        while left < right {
            let mid = left + (right - left) / 2;
            let function_offset = functions_start + 4 + (mid * FUNCTION_SIZE);

            let current_guid =
                FunctionGuid::from_digest(self.view.digest_at::<DbHash>(function_offset));

            match current_guid.cmp(function_guid) {
                std::cmp::Ordering::Less => left = mid + 1,
                std::cmp::Ordering::Greater => right = mid,
                std::cmp::Ordering::Equal => {
                    let constraint_index = self.view.u32_at(function_offset + DIGEST_SIZE) as usize;
                    let num_constraints =
                        self.view.u32_at(function_offset + DIGEST_SIZE + 4) as usize;

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
                    .map(|s| (c.guid, s))
            })
            .collect()
    }

    pub fn query_constraints_for_function_refs(
        &self,
        function_guid: &FunctionGuid,
    ) -> HashMap<ConstraintGuid, Vec<StringRef<'a>>> {
        self.iter_constraints(function_guid)
            .map(|c| (*c.guid(), c.iter_symbols().collect()))
            .collect()
    }

    fn string_ref_at_offset(&self, offset: u32) -> StringRef<'a> {
        let file_offset = self.header.strings_offset as usize + offset as usize;
        let len = self.view.u32_at(file_offset) as usize;
        StringRef {
            data: self.view.slice_at(file_offset + 4, len),
        }
    }
}

/// Flat triple-based writer.
///
/// Caller-provided invariants:
/// - `function_guids` is sorted ascending by GUID (binary search at read time).
/// - `triples` is sorted by `(func_id, constraint_id, symbol_id)`. Each tuple's
///   `func_id` indexes into `function_guids`, `constraint_id` into
///   `constraint_guids`, and `symbol_id` into `strings`.
/// - Triples are deduplicated.
/// - Every function in `function_guids` appears in at least one triple.
pub struct DbWriter<'a> {
    pub strings: &'a [String],
    pub constraint_guids: &'a [ConstraintGuid],
    pub function_guids: &'a [FunctionGuid],
    pub triples: &'a [(u32, u32, u32)],
}

impl<'a> DbWriter<'a> {
    pub fn write<W: Write + Seek>(&self, writer: &mut W) -> io::Result<()> {
        // Write header with placeholder offsets
        writer.write_all(MAGIC)?;
        writer.write_u8(VERSION)?;
        writer.write_u64::<LE>(0)?; // strings_offset placeholder
        writer.write_u64::<LE>(0)?; // constraints_offset placeholder
        writer.write_u64::<LE>(0)?; // constraint_strings_offset placeholder
        writer.write_u64::<LE>(0)?; // function_constraints_offset placeholder
        writer.write_u64::<LE>(0)?; // functions_offset placeholder

        // Strings section
        let strings_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.strings.len().try_into().unwrap())?;

        let mut string_byte_offsets = Vec::with_capacity(self.strings.len());
        let mut offset: u32 = 4;
        for string in self.strings {
            string_byte_offsets.push(offset);
            writer.write_u32::<LE>(string.len().try_into().unwrap())?;
            writer.write_all(string.as_bytes())?;
            offset += 4 + string.len() as u32;
        }

        // Constraints section: interner order, on-disk constraint_id == array index.
        let constraints_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.constraint_guids.len().try_into().unwrap())?;
        for guid in self.constraint_guids {
            writer.write_all(DbHash::digest_bytes(&guid.digest).as_ref())?;
        }

        // Symbol references section: one u32 byte-offset per triple.
        let constraint_strings_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.triples.len().try_into().unwrap())?;
        for &(_f, _c, s) in self.triples {
            writer.write_u32::<LE>(string_byte_offsets[s as usize])?;
        }

        // Function constraints section: one entry per distinct (func_id, constraint_id) run.
        // Also accumulate per-function fc counts for the functions section.
        let function_constraints_offset = writer.stream_position()?;
        let mut fc_per_func: Vec<u32> = vec![0; self.function_guids.len()];
        let fc_total_pos = writer.stream_position()?;
        writer.write_u32::<LE>(0)?; // patched after we know the count

        let mut fc_count: u32 = 0;
        let mut group_start = 0usize;
        let mut prev: Option<(u32, u32)> = None;
        for (i, &(f, c, _)) in self.triples.iter().enumerate() {
            match prev {
                Some(p) if p == (f, c) => {}
                Some((pf, pc)) => {
                    let count = (i - group_start) as u32;
                    writer.write_u32::<LE>(pc)?;
                    writer.write_u32::<LE>(count)?;
                    writer.write_u32::<LE>(group_start as u32)?;
                    fc_per_func[pf as usize] += 1;
                    fc_count += 1;
                    group_start = i;
                    prev = Some((f, c));
                }
                None => {
                    group_start = i;
                    prev = Some((f, c));
                }
            }
        }
        if let Some((pf, pc)) = prev {
            let count = (self.triples.len() - group_start) as u32;
            writer.write_u32::<LE>(pc)?;
            writer.write_u32::<LE>(count)?;
            writer.write_u32::<LE>(group_start as u32)?;
            fc_per_func[pf as usize] += 1;
            fc_count += 1;
        }

        // Functions section: sorted by GUID (caller responsibility).
        let functions_offset = writer.stream_position()?;
        writer.write_u32::<LE>(self.function_guids.len().try_into().unwrap())?;
        let mut fc_idx: u32 = 0;
        for (i, fg) in self.function_guids.iter().enumerate() {
            writer.write_all(DbHash::digest_bytes(&fg.digest).as_ref())?;
            writer.write_u32::<LE>(fc_idx)?;
            writer.write_u32::<LE>(fc_per_func[i])?;
            fc_idx += fc_per_func[i];
        }

        // Patch fc_count into function_constraints section header
        writer.seek(SeekFrom::Start(fc_total_pos))?;
        writer.write_u32::<LE>(fc_count)?;

        // Patch header offsets
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
    guid: ConstraintGuid,
    symbol_count: usize,
    string_index: usize,
}

impl<'db, 'a> ConstraintInfo<'db, 'a> {
    pub fn guid(&self) -> &ConstraintGuid {
        &self.guid
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

        let constraint_index = self.db.view.u32_at(offset) as usize;
        let constraint_guid = ConstraintGuid::from_digest(self.db.view.digest_at::<DbHash>(
            self.db.header.constraints_offset as usize + 4 + constraint_index * DIGEST_SIZE,
        ));
        let string_count = self.db.view.u32_at(offset + 4) as usize;
        let string_index = self.db.view.u32_at(offset + 8) as usize;

        self.current += 1;

        Some(ConstraintInfo {
            guid: constraint_guid,
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
        let string_offset = self.db.view.u32_at(offset);

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

        let func_guid =
            FunctionGuid::from_digest(self.db.view.digest_at::<DbHash>(function_offset));
        self.current += 1;

        Some(func_guid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Vec<u8> {
        let func_guid = FunctionGuid::from_digest(0x4141_4141_4141_4141);
        let constraint1 = ConstraintGuid::from_digest(0x4242_4242_4242_4242);
        let constraint2 = ConstraintGuid::from_digest(0x4343_4343_4343_4343);

        let strings = vec![
            "test_value_1".to_string(),
            "test_value_2".to_string(),
            "test_value_3".to_string(),
        ];
        let constraint_guids = vec![constraint1, constraint2];
        let function_guids = vec![func_guid];
        // (func_id, constraint_id, symbol_id) - sorted
        let triples = vec![
            (0, 0, 0), // constraint1 -> "test_value_1"
            (0, 0, 2), // constraint1 -> "test_value_3"
            (0, 1, 0), // constraint2 -> "test_value_1"
            (0, 1, 1), // constraint2 -> "test_value_2"
        ];

        let writer = DbWriter {
            strings: &strings,
            constraint_guids: &constraint_guids,
            function_guids: &function_guids,
            triples: &triples,
        };

        let mut buffer = vec![];
        writer
            .write(&mut std::io::Cursor::new(&mut buffer))
            .unwrap();
        buffer
    }

    #[test]
    fn test_write_and_read() {
        let func_guid = FunctionGuid::from_digest(0x4141_4141_4141_4141);
        let constraint1 = ConstraintGuid::from_digest(0x4242_4242_4242_4242);
        let constraint2 = ConstraintGuid::from_digest(0x4343_4343_4343_4343);

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
        let func_guid1 = FunctionGuid::from_digest(0x4141_4141_4141_4141);
        let func_guid2 = FunctionGuid::from_digest(0x4444_4444_4444_4444);

        let buffer = test_db();

        let db = Db::new(&buffer).unwrap();

        // Test direct constraint iterator lookup
        let mut iter = db.iter_constraints(&func_guid1);

        let c1 = iter.next().unwrap();
        assert_eq!(c1.symbol_count, 2);

        let c2 = iter.next().unwrap();
        assert_eq!(c2.symbol_count, 2);

        assert!(iter.next().is_none());

        // Test non-existent function
        assert_eq!(0, db.iter_constraints(&func_guid2).count());
    }
}
