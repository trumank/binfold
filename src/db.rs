use crate::hash::{HashAlgo, XxHash64};
use anyhow::{Result, bail};
use byteorder::{LE, WriteBytesExt};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Seek, SeekFrom, Write};

/// Hash algorithm pinned for the on-disk DB format.
pub type DbHash = XxHash64;
pub type FunctionGuid = crate::hash::FunctionGuid<DbHash>;
pub type BasicBlockGuid = crate::hash::BasicBlockGuid<DbHash>;
pub type SymbolGuid = crate::hash::SymbolGuid<DbHash>;
pub type ConstraintGuid = crate::hash::ConstraintGuid<DbHash>;
pub type BinaryGuid = crate::hash::BinaryGuid<DbHash>;

// File layout:
//
// [7 bytes] magic
// [1 byte]  version
// [8 bytes] directory_offset (u64 LE)
// [layer 0 body]
// [layer 1 body]
// ...
// [layer N-1 body]
// directory @ directory_offset:
//   [4 bytes] layer_count
//   for each layer:
//     [8 bytes] body_offset
//     [8 bytes] body_size
//
// Each layer body is self-contained and lives at offsets layer-relative
// to its own start. A layer body holds:
//
//   layer header
//     [8 bytes] strings_offset       (relative to layer start)
//     [8 bytes] constraints_offset
//     [8 bytes] constraint_strings_offset
//     [8 bytes] function_constraints_offset
//     [8 bytes] functions_offset
//     [8 bytes] binaries_offset
//
//   strings section
//     [4 bytes] count
//     for each:
//       [4 bytes] string length
//       [N bytes] UTF-8 string data
//
//   constraints section
//     [4 bytes] count
//     for each:
//       [DIGEST_SIZE bytes] ConstraintGUID
//
//   constraint strings section (one entry per (func, constraint, symbol) triple)
//     [4 bytes] count
//     for each:
//       [4 bytes] byte offset into strings section
//
//   function constraints section (one entry per distinct (func, constraint))
//     [4 bytes] count
//     for each:
//       [4 bytes] index into constraints section
//       [4 bytes] number of strings
//       [4 bytes] index into constraint strings section
//
//   functions section (sorted by GUID)
//     [4 bytes] count
//     for each:
//       [DIGEST_SIZE bytes] FunctionGUID
//       [4 bytes] index into function constraints section
//       [4 bytes] number of function constraints
//
//   binaries section (records which exes contributed to this layer; used to
//   skip already-ingested binaries on append)
//     [4 bytes] count
//     for each:
//       [DIGEST_SIZE bytes] BinaryGUID (xxhash64 of file contents)

const MAGIC: &[u8; 7] = b"BINFOLD";
const VERSION: u8 = 3;

const FILE_HEADER_SIZE: u64 = 16; // magic(7) + version(1) + directory_offset(8)
const LAYER_HEADER_SIZE: u64 = 48; // 6 × u64

const DIGEST_SIZE: usize = <DbHash as HashAlgo>::DIGEST_SIZE;
const CONSTRAINT_STRINGS_SIZE: usize = 4;
const FUNCTION_CONSTRAINTS_SIZE: usize = 4 + 4 + 4;
const FUNCTION_SIZE: usize = DIGEST_SIZE + 4 + 4;

/// A reference to a string in the database. Compares by byte content, so
/// references to identical strings in different layers are considered equal.
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

    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> PartialEq for StringRef<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<'a> Eq for StringRef<'a> {}

impl<'a> Hash for StringRef<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
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

/// A view over a single layer in the database.
pub struct LayerView<'a> {
    view: DataView<'a>,
    sections: SectionOffsets,
}

#[derive(Debug, Clone)]
pub struct SectionOffsets {
    pub strings_offset: u64,
    pub constraints_offset: u64,
    pub constraint_strings_offset: u64,
    pub function_constraints_offset: u64,
    pub functions_offset: u64,
    pub binaries_offset: u64,
}

impl<'a> LayerView<'a> {
    fn new(layer_bytes: &'a [u8]) -> Result<Self> {
        if (layer_bytes.len() as u64) < LAYER_HEADER_SIZE {
            bail!("Layer too small for header");
        }
        let view = DataView { data: layer_bytes };
        let sections = SectionOffsets {
            strings_offset: view.u64_at(0),
            constraints_offset: view.u64_at(8),
            constraint_strings_offset: view.u64_at(16),
            function_constraints_offset: view.u64_at(24),
            functions_offset: view.u64_at(32),
            binaries_offset: view.u64_at(40),
        };
        Ok(LayerView { view, sections })
    }

    pub fn sections(&self) -> &SectionOffsets {
        &self.sections
    }

    pub fn data_len(&self) -> usize {
        self.view.data.len()
    }

    pub fn function_count(&self) -> usize {
        self.view.u32_at(self.sections.functions_offset as usize) as usize
    }

    pub fn strings_count(&self) -> usize {
        self.view.u32_at(self.sections.strings_offset as usize) as usize
    }

    pub fn constraints_count(&self) -> usize {
        self.view.u32_at(self.sections.constraints_offset as usize) as usize
    }

    pub fn symbol_references_count(&self) -> usize {
        self.view
            .u32_at(self.sections.constraint_strings_offset as usize) as usize
    }

    pub fn function_constraints_count(&self) -> usize {
        self.view
            .u32_at(self.sections.function_constraints_offset as usize) as usize
    }

    pub fn binary_count(&self) -> usize {
        self.view.u32_at(self.sections.binaries_offset as usize) as usize
    }

    pub fn iter_binaries<'l>(&'l self) -> impl Iterator<Item = BinaryGuid> + 'l {
        let start = self.sections.binaries_offset as usize + 4;
        let count = self.binary_count();
        (0..count).map(move |i| {
            BinaryGuid::from_digest(self.view.digest_at::<DbHash>(start + i * DIGEST_SIZE))
        })
    }

    pub fn iter_functions<'l>(&'l self) -> LayerFunctionIterator<'l, 'a> {
        LayerFunctionIterator {
            layer: self,
            current: 0,
            total: self.function_count(),
        }
    }

    pub fn iter_constraints<'l>(
        &'l self,
        function_guid: &FunctionGuid,
    ) -> ConstraintIterator<'l, 'a> {
        let functions_start = self.sections.functions_offset as usize;
        let num_functions = self.view.u32_at(functions_start) as usize;

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
                        layer: self,
                        constraint_index,
                        current: 0,
                        total: num_constraints,
                    };
                }
            }
        }

        ConstraintIterator {
            layer: self,
            constraint_index: 0,
            current: 0,
            total: 0,
        }
    }

    fn string_ref_at_offset(&self, offset: u32) -> StringRef<'a> {
        let file_offset = self.sections.strings_offset as usize + offset as usize;
        let len = self.view.u32_at(file_offset) as usize;
        StringRef {
            data: self.view.slice_at(file_offset + 4, len),
        }
    }
}

pub struct Db<'a> {
    layers: Vec<LayerView<'a>>,
}

impl<'a> Db<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        Self::from_buffers(&[data])
    }

    /// Build a Db whose layers are the concatenation of all layers from each
    /// input buffer, in the given order. Lookups iterate every layer, so two
    /// files contributing the same function GUID merge naturally.
    pub fn from_buffers(buffers: &[&'a [u8]]) -> Result<Self> {
        let mut layers = Vec::new();
        for data in buffers {
            Self::extend_layers(data, &mut layers)?;
        }
        Ok(Db { layers })
    }

    fn extend_layers(data: &'a [u8], layers: &mut Vec<LayerView<'a>>) -> Result<()> {
        if (data.len() as u64) < FILE_HEADER_SIZE {
            bail!("File too small");
        }
        let view = DataView { data };
        if view.slice_at(0, 7) != MAGIC {
            bail!("Invalid magic");
        }
        let version = data[7];
        if version != VERSION {
            bail!("Database version mismatch: file is v{version}, expected v{VERSION}");
        }
        let directory_offset = view.u64_at(8) as usize;
        if directory_offset + 4 > data.len() {
            bail!("Directory offset out of bounds");
        }
        let layer_count = view.u32_at(directory_offset) as usize;
        let entries_start = directory_offset + 4;
        let entries_end = entries_start + layer_count * 16;
        if entries_end > data.len() {
            bail!("Layer directory out of bounds");
        }

        layers.reserve(layer_count);
        for i in 0..layer_count {
            let entry = entries_start + i * 16;
            let body_off = view.u64_at(entry) as usize;
            let body_size = view.u64_at(entry + 8) as usize;
            if body_off + body_size > data.len() {
                bail!("Layer {i} body extends past end of file");
            }
            layers.push(LayerView::new(&data[body_off..body_off + body_size])?);
        }
        Ok(())
    }

    pub fn layers(&self) -> &[LayerView<'a>] {
        &self.layers
    }

    /// Iterate every function GUID across all layers. May yield duplicates
    /// when the same GUID appears in multiple layers.
    pub fn iter_functions<'db>(&'db self) -> impl Iterator<Item = FunctionGuid> + 'db {
        self.layers.iter().flat_map(|l| l.iter_functions())
    }

    /// Iterate constraints for a function across all layers. May yield the
    /// same constraint GUID multiple times (once per layer that has it).
    pub fn iter_constraints<'db>(
        &'db self,
        function_guid: &FunctionGuid,
    ) -> impl Iterator<Item = ConstraintInfo<'db, 'a>> + 'db {
        let guid = *function_guid;
        self.layers
            .iter()
            .flat_map(move |l| l.iter_constraints(&guid))
    }

    pub fn query_constraints_for_function(
        &self,
        function_guid: &FunctionGuid,
    ) -> Result<HashMap<ConstraintGuid, Vec<&'a str>>> {
        let mut map: HashMap<ConstraintGuid, std::collections::HashSet<&'a str>> = HashMap::new();
        for c in self.iter_constraints(function_guid) {
            let entry = map.entry(*c.guid()).or_default();
            for s in c.iter_symbols() {
                entry.insert(s.as_str()?);
            }
        }
        Ok(map
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect())
    }

    pub fn query_constraints_for_function_refs(
        &self,
        function_guid: &FunctionGuid,
    ) -> HashMap<ConstraintGuid, std::collections::HashSet<StringRef<'a>>> {
        let mut map: HashMap<ConstraintGuid, std::collections::HashSet<StringRef<'a>>> =
            HashMap::new();
        for c in self.iter_constraints(function_guid) {
            map.entry(*c.guid()).or_default().extend(c.iter_symbols());
        }
        map
    }

    /// True if any layer's binaries section contains this guid.
    pub fn contains_binary(&self, guid: &BinaryGuid) -> bool {
        self.layers
            .iter()
            .any(|l| l.iter_binaries().any(|g| &g == guid))
    }

    /// Set of every binary GUID recorded across all layers.
    pub fn all_binaries(&self) -> std::collections::HashSet<BinaryGuid> {
        self.layers.iter().flat_map(|l| l.iter_binaries()).collect()
    }
}

/// In-memory description of one layer. Caller-provided invariants:
/// - `function_guids` is sorted ascending by GUID (binary search at read time).
/// - `triples` is sorted by `(func_id, constraint_id, symbol_id)`. Each tuple's
///   `func_id` indexes into `function_guids`, `constraint_id` into
///   `constraint_guids`, and `symbol_id` into `strings`.
/// - Triples are deduplicated.
/// - Every function in `function_guids` appears in at least one triple.
pub struct Layer<'a> {
    pub strings: &'a [String],
    pub constraint_guids: &'a [ConstraintGuid],
    pub function_guids: &'a [FunctionGuid],
    pub triples: &'a [(u32, u32, u32)],
    pub binaries: &'a [BinaryGuid],
}

impl<'a> Layer<'a> {
    /// Writes a self-contained layer body. Returns the number of bytes written.
    pub fn write_body<W: Write + Seek>(&self, writer: &mut W) -> io::Result<u64> {
        let body_start = writer.stream_position()?;

        // Reserve layer header (6 × u64).
        for _ in 0..6 {
            writer.write_u64::<LE>(0)?;
        }

        // Strings section.
        let strings_offset = writer.stream_position()? - body_start;
        writer.write_u32::<LE>(self.strings.len().try_into().unwrap())?;

        let mut string_byte_offsets = Vec::with_capacity(self.strings.len());
        let mut offset: u32 = 4;
        for string in self.strings {
            string_byte_offsets.push(offset);
            writer.write_u32::<LE>(string.len().try_into().unwrap())?;
            writer.write_all(string.as_bytes())?;
            offset += 4 + string.len() as u32;
        }

        // Constraints section.
        let constraints_offset = writer.stream_position()? - body_start;
        writer.write_u32::<LE>(self.constraint_guids.len().try_into().unwrap())?;
        for guid in self.constraint_guids {
            writer.write_all(DbHash::digest_bytes(&guid.digest).as_ref())?;
        }

        // Symbol references section.
        let constraint_strings_offset = writer.stream_position()? - body_start;
        writer.write_u32::<LE>(self.triples.len().try_into().unwrap())?;
        for &(_f, _c, s) in self.triples {
            writer.write_u32::<LE>(string_byte_offsets[s as usize])?;
        }

        // Function constraints section.
        let function_constraints_offset = writer.stream_position()? - body_start;
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

        // Functions section.
        let functions_offset = writer.stream_position()? - body_start;
        writer.write_u32::<LE>(self.function_guids.len().try_into().unwrap())?;
        let mut fc_idx: u32 = 0;
        for (i, fg) in self.function_guids.iter().enumerate() {
            writer.write_all(DbHash::digest_bytes(&fg.digest).as_ref())?;
            writer.write_u32::<LE>(fc_idx)?;
            writer.write_u32::<LE>(fc_per_func[i])?;
            fc_idx += fc_per_func[i];
        }

        // Binaries section.
        let binaries_offset = writer.stream_position()? - body_start;
        writer.write_u32::<LE>(self.binaries.len().try_into().unwrap())?;
        for guid in self.binaries {
            writer.write_all(DbHash::digest_bytes(&guid.digest).as_ref())?;
        }

        let body_end = writer.stream_position()?;

        // Patch fc_count.
        writer.seek(SeekFrom::Start(fc_total_pos))?;
        writer.write_u32::<LE>(fc_count)?;

        // Patch layer header.
        writer.seek(SeekFrom::Start(body_start))?;
        writer.write_u64::<LE>(strings_offset)?;
        writer.write_u64::<LE>(constraints_offset)?;
        writer.write_u64::<LE>(constraint_strings_offset)?;
        writer.write_u64::<LE>(function_constraints_offset)?;
        writer.write_u64::<LE>(functions_offset)?;
        writer.write_u64::<LE>(binaries_offset)?;

        writer.seek(SeekFrom::Start(body_end))?;
        Ok(body_end - body_start)
    }
}

/// Write a fresh database file containing the given layers.
pub fn write_database<W: Write + Seek>(layers: &[&Layer<'_>], writer: &mut W) -> io::Result<()> {
    // File header.
    writer.write_all(MAGIC)?;
    writer.write_u8(VERSION)?;
    writer.write_u64::<LE>(0)?; // directory_offset placeholder

    let mut entries = Vec::with_capacity(layers.len());
    for layer in layers {
        let body_off = writer.stream_position()?;
        let body_size = layer.write_body(writer)?;
        entries.push((body_off, body_size));
    }

    let directory_offset = writer.stream_position()?;
    writer.write_u32::<LE>(entries.len().try_into().unwrap())?;
    for (off, size) in &entries {
        writer.write_u64::<LE>(*off)?;
        writer.write_u64::<LE>(*size)?;
    }

    writer.seek(SeekFrom::Start(8))?;
    writer.write_u64::<LE>(directory_offset)?;
    Ok(())
}

/// Append a layer to an existing database file. Truncates the existing
/// directory, writes the new layer body where it sat, then writes a fresh
/// directory and patches the file header.
pub fn append_layer<F: Read + Write + Seek>(file: &mut F, layer: &Layer<'_>) -> io::Result<()> {
    let mut header = [0u8; FILE_HEADER_SIZE as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    if &header[0..7] != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid magic"));
    }
    if header[7] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Database version mismatch: file is v{}, expected v{VERSION}",
                header[7]
            ),
        ));
    }
    let directory_offset = u64::from_le_bytes(header[8..16].try_into().unwrap());

    file.seek(SeekFrom::Start(directory_offset))?;
    let mut count_buf = [0u8; 4];
    file.read_exact(&mut count_buf)?;
    let layer_count = u32::from_le_bytes(count_buf) as usize;
    let mut entries = Vec::with_capacity(layer_count + 1);
    for _ in 0..layer_count {
        let mut buf = [0u8; 16];
        file.read_exact(&mut buf)?;
        let off = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        entries.push((off, size));
    }

    // Reads are done; switch to a buffered writer for the body (millions of
    // small writes through write_body would otherwise be one syscall each).
    let mut writer = std::io::BufWriter::new(file);

    writer.seek(SeekFrom::Start(directory_offset))?;
    let body_off = directory_offset;
    let body_size = layer.write_body(&mut writer)?;
    entries.push((body_off, body_size));

    let new_directory_offset = writer.stream_position()?;
    writer.write_u32::<LE>(entries.len().try_into().unwrap())?;
    for (off, size) in &entries {
        writer.write_u64::<LE>(*off)?;
        writer.write_u64::<LE>(*size)?;
    }

    writer.seek(SeekFrom::Start(8))?;
    writer.write_u64::<LE>(new_directory_offset)?;
    writer.flush()?;
    Ok(())
}

pub struct ConstraintIterator<'l, 'a> {
    layer: &'l LayerView<'a>,
    constraint_index: usize,
    current: usize,
    total: usize,
}

pub struct ConstraintInfo<'l, 'a> {
    layer: &'l LayerView<'a>,
    guid: ConstraintGuid,
    symbol_count: usize,
    string_index: usize,
}

impl<'l, 'a> ConstraintInfo<'l, 'a> {
    pub fn guid(&self) -> &ConstraintGuid {
        &self.guid
    }
    pub fn symbol_count(&self) -> usize {
        self.symbol_count
    }

    pub fn iter_symbols(&self) -> SymbolIterator<'l, 'a> {
        SymbolIterator {
            layer: self.layer,
            string_index: self.string_index,
            current: 0,
            total: self.symbol_count,
        }
    }
}

impl<'l, 'a> Iterator for ConstraintIterator<'l, 'a> {
    type Item = ConstraintInfo<'l, 'a>;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.current;
        (remaining, Some(remaining))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.total {
            return None;
        }

        let constraints_start = self.layer.sections.function_constraints_offset as usize + 4;
        let offset = constraints_start
            + ((self.constraint_index + self.current) * FUNCTION_CONSTRAINTS_SIZE);

        let constraint_index = self.layer.view.u32_at(offset) as usize;
        let constraint_guid = ConstraintGuid::from_digest(self.layer.view.digest_at::<DbHash>(
            self.layer.sections.constraints_offset as usize + 4 + constraint_index * DIGEST_SIZE,
        ));
        let string_count = self.layer.view.u32_at(offset + 4) as usize;
        let string_index = self.layer.view.u32_at(offset + 8) as usize;

        self.current += 1;

        Some(ConstraintInfo {
            guid: constraint_guid,
            symbol_count: string_count,
            string_index,
            layer: self.layer,
        })
    }
}

pub struct SymbolIterator<'l, 'a> {
    layer: &'l LayerView<'a>,
    string_index: usize,
    current: usize,
    total: usize,
}

impl<'l, 'a> Iterator for SymbolIterator<'l, 'a> {
    type Item = StringRef<'a>;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.current;
        (remaining, Some(remaining))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.total {
            return None;
        }

        let constraint_strings_start = self.layer.sections.constraint_strings_offset as usize + 4;
        let offset =
            constraint_strings_start + (self.string_index + self.current) * CONSTRAINT_STRINGS_SIZE;
        let string_offset = self.layer.view.u32_at(offset);

        self.current += 1;
        Some(self.layer.string_ref_at_offset(string_offset))
    }
}

pub struct LayerFunctionIterator<'l, 'a> {
    layer: &'l LayerView<'a>,
    current: usize,
    total: usize,
}

impl<'l, 'a> Iterator for LayerFunctionIterator<'l, 'a> {
    type Item = FunctionGuid;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.current;
        (remaining, Some(remaining))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.total {
            return None;
        }

        let functions_start = self.layer.sections.functions_offset as usize;
        let function_offset = functions_start + 4 + (self.current * FUNCTION_SIZE);

        let func_guid =
            FunctionGuid::from_digest(self.layer.view.digest_at::<DbHash>(function_offset));
        self.current += 1;

        Some(func_guid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Cursor;

    fn build_layer_buffer(
        strings: &[String],
        constraint_guids: &[ConstraintGuid],
        function_guids: &[FunctionGuid],
        triples: &[(u32, u32, u32)],
    ) -> Vec<u8> {
        build_layer_buffer_with_binaries(strings, constraint_guids, function_guids, triples, &[])
    }

    fn build_layer_buffer_with_binaries(
        strings: &[String],
        constraint_guids: &[ConstraintGuid],
        function_guids: &[FunctionGuid],
        triples: &[(u32, u32, u32)],
        binaries: &[BinaryGuid],
    ) -> Vec<u8> {
        let layer = Layer {
            strings,
            constraint_guids,
            function_guids,
            triples,
            binaries,
        };
        let mut buffer = vec![];
        write_database(&[&layer], &mut Cursor::new(&mut buffer)).unwrap();
        buffer
    }

    fn sample_db() -> Vec<u8> {
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
        let triples = vec![(0, 0, 0), (0, 0, 2), (0, 1, 0), (0, 1, 1)];

        build_layer_buffer(&strings, &constraint_guids, &function_guids, &triples)
    }

    #[test]
    fn test_write_and_read() {
        let func_guid = FunctionGuid::from_digest(0x4141_4141_4141_4141);
        let constraint1 = ConstraintGuid::from_digest(0x4242_4242_4242_4242);
        let constraint2 = ConstraintGuid::from_digest(0x4343_4343_4343_4343);

        let buffer = sample_db();

        let db = Db::new(&buffer).unwrap();
        let constraints = db.query_constraints_for_function(&func_guid).unwrap();

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

        let buffer = sample_db();

        let db = Db::new(&buffer).unwrap();

        let mut iter = db.iter_constraints(&func_guid1);

        let c1 = iter.next().unwrap();
        assert_eq!(c1.symbol_count, 2);

        let c2 = iter.next().unwrap();
        assert_eq!(c2.symbol_count, 2);

        assert!(iter.next().is_none());

        assert_eq!(0, db.iter_constraints(&func_guid2).count());
    }

    #[test]
    fn test_append_matches_combined() {
        // Layer A: function g1 with constraint c1 → {"a"}
        // Layer B: function g1 with constraint c1 → {"b"} and c2 → {"c"}
        // Combined-in-one-shot: g1 with c1 → {"a","b"} and c2 → {"c"}
        // Build via append; expect identical results.
        let g1 = FunctionGuid::from_digest(0x1111_1111_1111_1111);
        let c1 = ConstraintGuid::from_digest(0x2222_2222_2222_2222);
        let c2 = ConstraintGuid::from_digest(0x3333_3333_3333_3333);

        // Build the appended file.
        let buffer_a = {
            let strings = vec!["a".to_string()];
            let constraint_guids = vec![c1];
            let function_guids = vec![g1];
            let triples = vec![(0, 0, 0)];
            build_layer_buffer(&strings, &constraint_guids, &function_guids, &triples)
        };

        let mut file = std::io::Cursor::new(buffer_a);
        let strings_b = vec!["b".to_string(), "c".to_string()];
        let constraint_guids_b = vec![c1, c2];
        let function_guids_b = vec![g1];
        let triples_b = vec![(0, 0, 0), (0, 1, 1)];
        let layer_b = Layer {
            strings: &strings_b,
            constraint_guids: &constraint_guids_b,
            function_guids: &function_guids_b,
            triples: &triples_b,
            binaries: &[],
        };
        append_layer(&mut file, &layer_b).unwrap();
        let appended_bytes = file.into_inner();

        // Build the combined file in one shot.
        let combined_bytes = {
            let strings = vec!["a".to_string(), "b".to_string(), "c".to_string()];
            let constraint_guids = vec![c1, c2];
            let function_guids = vec![g1];
            // (g1, c1, "a"), (g1, c1, "b"), (g1, c2, "c")
            let triples = vec![(0, 0, 0), (0, 0, 1), (0, 1, 2)];
            build_layer_buffer(&strings, &constraint_guids, &function_guids, &triples)
        };

        let appended_db = Db::new(&appended_bytes).unwrap();
        let combined_db = Db::new(&combined_bytes).unwrap();

        let appended = appended_db.query_constraints_for_function(&g1).unwrap();
        let combined = combined_db.query_constraints_for_function(&g1).unwrap();

        let to_set =
            |m: &HashMap<ConstraintGuid, Vec<&str>>| -> HashMap<ConstraintGuid, HashSet<String>> {
                m.iter()
                    .map(|(k, v)| (*k, v.iter().map(|s| s.to_string()).collect()))
                    .collect()
            };
        assert_eq!(to_set(&appended), to_set(&combined));
    }

    #[test]
    fn test_binaries_section_roundtrip() {
        let g1 = FunctionGuid::from_digest(0x1111_1111_1111_1111);
        let c1 = ConstraintGuid::from_digest(0x2222_2222_2222_2222);
        let bin1 = BinaryGuid::from_digest(0xAAAA_AAAA_AAAA_AAAA);
        let bin2 = BinaryGuid::from_digest(0xBBBB_BBBB_BBBB_BBBB);

        let buffer = build_layer_buffer_with_binaries(
            &["x".to_string()],
            &[c1],
            &[g1],
            &[(0, 0, 0)],
            &[bin1, bin2],
        );

        let db = Db::new(&buffer).unwrap();
        assert!(db.contains_binary(&bin1));
        assert!(db.contains_binary(&bin2));
        assert!(!db.contains_binary(&BinaryGuid::from_digest(0xCCCC)));
        assert_eq!(db.all_binaries().len(), 2);

        // After append, both layers' binaries are visible.
        let bin3 = BinaryGuid::from_digest(0xCCCC_CCCC_CCCC_CCCC);
        let mut file = std::io::Cursor::new(buffer);
        let strings = vec!["y".to_string()];
        let cguids = vec![c1];
        let fguids = vec![g1];
        let triples = vec![(0, 0, 0)];
        let bins = vec![bin3];
        let layer = Layer {
            strings: &strings,
            constraint_guids: &cguids,
            function_guids: &fguids,
            triples: &triples,
            binaries: &bins,
        };
        append_layer(&mut file, &layer).unwrap();
        let bytes = file.into_inner();
        let db = Db::new(&bytes).unwrap();
        assert!(db.contains_binary(&bin1));
        assert!(db.contains_binary(&bin2));
        assert!(db.contains_binary(&bin3));
        assert_eq!(db.all_binaries().len(), 3);
    }
}
