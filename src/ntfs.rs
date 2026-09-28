//! NTFS volumes: list allocated files (with alternate data streams) and
//! stream their content.
//!
//! File-system structures are read by the `ntfs` crate. That crate can panic
//! on some malformed structures (it unwraps values read from disk), and a
//! forensic tool must not crash on a hostile image, so every call into it is
//! guarded: a panic becomes an [`io::Error`] saying the structure is corrupt.

use std::collections::HashSet;
use std::io::{self, Read, Seek};
use std::panic::{self, AssertUnwindSafe};

use ntfs::structured_values::{NtfsFileName, NtfsFileNamespace};
use ntfs::{Ntfs, NtfsAttributeType, NtfsFile};

use crate::window::Window;

/// Record number of the root directory.
const ROOT_RECORD: u64 = 5;
/// Directory depth beyond which listing stops (hostile or cyclic trees).
const MAX_DEPTH: usize = 256;
/// Upper bound on files listed per volume.
const MAX_FILES: usize = 10_000_000;

/// One file, or one alternate data stream of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Path components from the volume root.
    pub path: Vec<String>,
    /// MFT record number.
    pub record: u64,
    /// Alternate data stream name, or `None` for the default stream.
    pub stream: Option<String>,
    /// Declared size of the stream in bytes. Sparse streams (such as
    /// `$UsnJrnl:$J`) legitimately declare far more than they store, and a
    /// corrupt record can declare anything: bound what you read.
    pub size: u64,
}

impl FileEntry {
    /// The path joined with `\`, with `:stream` appended for alternate data
    /// streams, the way Windows writes it.
    #[must_use]
    pub fn display_path(&self) -> String {
        let path = self.path.join("\\");
        match &self.stream {
            Some(stream) => format!("{path}:{stream}"),
            None => path,
        }
    }
}

/// An NTFS volume at a byte range of a disk.
pub struct NtfsVolume {
    ntfs: Ntfs,
    start: u64,
    length: u64,
}

impl NtfsVolume {
    /// Open the NTFS volume occupying `start..start + length` of `disk`.
    ///
    /// # Errors
    /// When the range doesn't hold a readable NTFS volume.
    pub fn open<R: Read + Seek>(disk: &mut R, start: u64, length: u64) -> io::Result<Self> {
        let mut window = Window::new(disk, start, length);
        let ntfs = guarded(|| {
            let mut ntfs = Ntfs::new(&mut window)?;
            // Needed to look up named streams by name.
            ntfs.read_upcase_table(&mut window)?;
            Ok(ntfs)
        })?;
        Ok(Self {
            ntfs,
            start,
            length,
        })
    }

    /// Every allocated file and alternate data stream, depth first, in
    /// directory-index order. Directories themselves are not listed.
    ///
    /// # Errors
    /// On read errors or corrupt structures.
    pub fn files<R: Read + Seek>(&self, disk: &mut R) -> io::Result<Vec<FileEntry>> {
        let mut window = Window::new(disk, self.start, self.length);
        let mut files = Vec::new();
        let mut visited = HashSet::from([ROOT_RECORD]);
        let mut pending = vec![(ROOT_RECORD, Vec::<String>::new())];
        while let Some((record, path)) = pending.pop() {
            if path.len() > MAX_DEPTH || files.len() > MAX_FILES {
                break;
            }
            for child in self.children(&mut window, record)? {
                let mut child_path = path.clone();
                child_path.push(child.name);
                let streams = self.streams(&mut window, child.record)?;
                if child.is_directory {
                    if visited.insert(child.record) {
                        pending.push((child.record, child_path.clone()));
                    }
                    files.extend(named_only(streams, &child_path, child.record));
                } else {
                    files.extend(entries_for(streams, &child_path, child.record));
                }
            }
        }
        Ok(files)
    }

    /// Stream the content of `entry` into `consume`.
    ///
    /// Sparse ranges read as zeros without touching the disk, so a hostile
    /// or sparse stream can yield an enormous amount of data: consumers must
    /// bound what they read (e.g. with [`Read::take`]).
    ///
    /// # Errors
    /// When the file or stream can't be read.
    pub fn read<R: Read + Seek>(
        &self,
        disk: &mut R,
        entry: &FileEntry,
        consume: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut window = Window::new(disk, self.start, self.length);
        let stream_name = entry.stream.as_deref().unwrap_or("");
        let file = guarded(|| self.ntfs.file(&mut window, entry.record))?;
        let item = guarded(|| {
            file.data(&mut window, stream_name)
                .unwrap_or_else(|| Err(missing_stream(&file)))
        })?;
        let attribute = guarded(|| item.to_attribute())?;
        let value = guarded(|| attribute.value(&mut window))?;
        let mut reader = value.attach(&mut window);
        consume(&mut reader)
    }

    /// Named children of directory `record`: long names only (8.3 aliases
    /// and the root's `.` entry are skipped).
    fn children<W: Read + Seek>(&self, window: &mut W, record: u64) -> io::Result<Vec<Child>> {
        guarded(|| {
            let directory = self.ntfs.file(window, record)?;
            let index = directory.directory_index(window)?;
            let mut entries = index.entries();
            let mut children = Vec::new();
            while let Some(entry) = entries.next(window) {
                let entry = entry?;
                let Some(key) = entry.key() else { continue };
                let key: NtfsFileName = key?;
                if key.namespace() == NtfsFileNamespace::Dos {
                    continue;
                }
                let name = key.name().to_string_lossy();
                if name == "." {
                    continue;
                }
                let child = entry.file_reference().file_record_number();
                children.push(Child {
                    name,
                    record: child,
                    is_directory: key.is_directory(),
                });
            }
            Ok(children)
        })
    }

    /// `(stream name, size)` of every `$DATA` attribute of `record`; the
    /// default stream has an empty name.
    fn streams<W: Read + Seek>(
        &self,
        window: &mut W,
        record: u64,
    ) -> io::Result<Vec<(String, u64)>> {
        guarded(|| {
            let file = self.ntfs.file(window, record)?;
            let mut attributes = file.attributes();
            let mut streams = Vec::new();
            while let Some(item) = attributes.next(window) {
                let item = item?;
                let attribute = item.to_attribute()?;
                if attribute.ty()? == NtfsAttributeType::Data {
                    streams.push((
                        attribute.name()?.to_string_lossy(),
                        attribute.value_length(),
                    ));
                }
            }
            Ok(streams)
        })
    }
}

struct Child {
    name: String,
    record: u64,
    is_directory: bool,
}

/// A file's default stream and its alternate data streams.
fn entries_for(streams: Vec<(String, u64)>, path: &[String], record: u64) -> Vec<FileEntry> {
    streams
        .into_iter()
        .map(|(name, size)| FileEntry {
            path: path.to_vec(),
            record,
            stream: (!name.is_empty()).then_some(name),
            size,
        })
        .collect()
}

/// Only the alternate data streams (directories have no default stream).
fn named_only(streams: Vec<(String, u64)>, path: &[String], record: u64) -> Vec<FileEntry> {
    let named = streams
        .into_iter()
        .filter(|(name, _)| !name.is_empty())
        .collect();
    entries_for(named, path, record)
}

fn missing_stream(file: &NtfsFile<'_>) -> ntfs::NtfsError {
    ntfs::NtfsError::AttributeNotFound {
        position: file.position(),
        ty: NtfsAttributeType::Data,
    }
}

/// Run a call into the `ntfs` crate, turning its errors and panics into
/// [`io::Error`]s.
fn guarded<T>(call: impl FnOnce() -> ntfs::Result<T>) -> io::Result<T> {
    match panic::catch_unwind(AssertUnwindSafe(call)) {
        Ok(result) => result.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "corrupt NTFS structure",
        )),
    }
}
