use memmap2::{Mmap, MmapOptions};
use pdb::{Source, SourceSlice, SourceView};
use std::fmt;
use std::fs::File;
use std::io;
use std::path::Path;

/// A memory-mapped PDB source implementation
pub struct MmapSource {
    mmap: Mmap,
}

impl MmapSource {
    pub fn new(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        Ok(Self { mmap })
    }
}

impl fmt::Debug for MmapSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MmapSource({} bytes)", self.mmap.len())
    }
}

/// View into memory-mapped data
struct MmapView {
    data: Vec<u8>,
}

impl fmt::Debug for MmapView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MmapView({} bytes)", self.data.len())
    }
}

impl<'s> SourceView<'s> for MmapView {
    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl<'s> Source<'s> for MmapSource {
    fn view(
        &mut self,
        slices: &[SourceSlice],
    ) -> Result<Box<dyn SourceView<'s> + Send + Sync>, io::Error> {
        let total_size = slices.iter().map(|s| s.size).sum();
        let mut data = Vec::with_capacity(total_size);

        for slice in slices {
            let start = slice.offset as usize;
            let end = start + slice.size;

            if end > self.mmap.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Requested slice extends past end of file: {} > {}",
                        end,
                        self.mmap.len()
                    ),
                ));
            }

            data.extend_from_slice(&self.mmap[start..end]);
        }

        Ok(Box::new(MmapView { data }))
    }
}
