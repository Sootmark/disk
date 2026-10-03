//! Loose `$MFT` files, as triage collections (KAPE, Velociraptor,
//! acquire) copy them out of a volume: every file record, deleted ones
//! included, without the rest of the volume.

use std::fmt;
use std::io::{self, Read};

use super::boot::MAX_RECORD_SIZE;
use super::record::{Attribute, Body};
use super::table::{Node, Table, ORPHANS};
use crate::times::Times;

/// The smallest record size accepted: one sector.
const MIN_RECORD_SIZE: usize = 512;
/// Bytes searched for a record declaring the record size.
const PROBE_LENGTH: u64 = 64 * 1024;

/// The file records of an MFT.
///
/// ```no_run
/// let mft = sootmark_disk::Mft::parse(&std::fs::read("C/$MFT")?);
/// for file in mft.files.iter().filter(|f| !f.in_use) {
///     println!("deleted: {} (record {})", file.display_path(), file.record);
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mft {
    /// One per base record, in use or deleted, by record number. Extension
    /// records are merged into their base record, not listed.
    pub files: Vec<MftFile>,
    /// What couldn't be read (damaged records, a truncated end): the rest
    /// is still listed.
    pub problems: Vec<MftProblem>,
}

/// A file, or a directory, as its MFT record describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MftFile {
    /// MFT record number.
    pub record: u64,
    /// Sequence number: incremented each time the record is freed, so a
    /// reference to an older file in this record no longer matches.
    pub sequence: u16,
    /// False for a deleted file (its record freed, not yet reused).
    pub in_use: bool,
    /// A directory rather than a file.
    pub is_directory: bool,
    /// `$STANDARD_INFORMATION` times (what Windows shows, and what
    /// timestomping rewrites).
    pub times: Times,
    /// Every `$FILE_NAME`: one per hard link, plus 8.3 aliases.
    pub names: Vec<FileName>,
    /// `$DATA` streams, by name: the default stream first, then
    /// alternate data streams. Directories normally have none.
    pub streams: Vec<DataStream>,
    /// Path components from the volume root, rebuilt from parent
    /// references (from the primary name, see [`MftFile::display_path`]).
    pub path: Vec<String>,
}

impl MftFile {
    /// The path joined with `\`: empty for the root, and for a record with
    /// no name.
    ///
    /// Built from a Windows long name (else a POSIX name, else an 8.3
    /// alias). A deleted file keeps its last path, through deleted parent
    /// directories. A file whose parent chain is broken (a parent's record
    /// reused for another file, missing, or cyclic) is placed under
    /// `$OrphanFiles`, as The Sleuth Kit does, below as much of the chain
    /// as is known: see [`MftFile::is_orphan`].
    #[must_use]
    pub fn display_path(&self) -> String {
        self.path.join("\\")
    }

    /// Whether the parent chain is broken, so the path starts at
    /// `$OrphanFiles` rather than the root.
    #[must_use]
    pub fn is_orphan(&self) -> bool {
        self.path.first().is_some_and(|first| first == ORPHANS)
    }
}

/// A `$FILE_NAME` attribute: a name and the directory it is in, with times
/// and sizes of its own (set when the name was created or renamed, and
/// rarely after: compare them with [`MftFile::times`] to spot timestomping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    /// The name.
    pub name: String,
    /// Which naming rules the name follows.
    pub namespace: Namespace,
    /// Record number of the parent directory.
    pub parent: u64,
    /// Sequence number the parent directory had when the name was created.
    pub parent_sequence: u16,
    /// The name's own times (UTC).
    pub times: Times,
    /// Allocated size as of the name's last update.
    pub allocated_size: u64,
    /// Real size as of the name's last update (often zero or stale: the
    /// streams' sizes are authoritative).
    pub size: u64,
}

/// The namespace of a `$FILE_NAME`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    /// Case-sensitive, any character but `/` and NUL (Linux tools, WSL).
    Posix,
    /// A Windows long name, with an 8.3 alias in another `$FILE_NAME`.
    Win32,
    /// An 8.3 alias of a Windows long name.
    Dos,
    /// A name valid both as a Windows long name and as an 8.3 name.
    Win32AndDos,
    /// Not a namespace NTFS defines.
    Other(u8),
}

impl Namespace {
    pub(crate) fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Posix,
            1 => Self::Win32,
            2 => Self::Dos,
            3 => Self::Win32AndDos,
            other => Self::Other(other),
        }
    }

    /// Preference when picking a name to build paths from (lowest first).
    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::Win32 | Self::Win32AndDos => 0,
            Self::Posix => 1,
            Self::Other(_) => 2,
            Self::Dos => 3,
        }
    }
}

/// A `$DATA` stream of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataStream {
    /// Alternate data stream name, or `None` for the default stream.
    pub name: Option<String>,
    /// Declared size in bytes.
    pub size: u64,
    /// The content, when it is stored in the record itself (small streams
    /// such as `Zone.Identifier`). `None` for content stored in clusters,
    /// which a loose `$MFT` doesn't hold.
    pub resident: Option<Vec<u8>>,
}

/// Something that couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MftProblem {
    /// The record concerned, or `None` for the file as a whole.
    pub record: Option<u64>,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for MftProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.record {
            Some(record) => write!(f, "record {record}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl Mft {
    /// Read a loose `$MFT` held in memory. Never fails: what can't be read
    /// is in [`Mft::problems`].
    #[must_use]
    pub fn parse(mft: &[u8]) -> Self {
        Self::read(mft).unwrap_or_default() // reading memory never fails
    }

    /// Read a loose `$MFT` record by record, without holding it in memory.
    ///
    /// The record size (1024 or 4096 bytes) is the one the first records
    /// declare. Update-sequence fixups are verified: a torn write makes its
    /// record a problem, never silently accepted data.
    ///
    /// # Errors
    /// Only when `mft` fails to read.
    pub fn read<R: Read>(mut mft: R) -> io::Result<Self> {
        let mut head = Vec::new();
        (&mut mft).take(PROBE_LENGTH).read_to_end(&mut head)?;
        let Some(record_size) = record_size(&head) else {
            return Ok(Self {
                files: Vec::new(),
                problems: vec![MftProblem {
                    record: None,
                    message: "not an MFT: no file record found".to_owned(),
                }],
            });
        };
        let table = Table::read(head.as_slice().chain(mft), record_size)?;
        Ok(Self::from_table(table))
    }

    pub(crate) fn from_table(table: Table) -> Self {
        let paths: Vec<Vec<String>> = table
            .nodes
            .keys()
            .map(|&number| table.path_of(number).unwrap_or_default())
            .collect();
        let files = table
            .nodes
            .into_iter()
            .zip(paths)
            .map(|((record, node), path)| MftFile {
                record,
                sequence: node.sequence,
                in_use: node.in_use,
                is_directory: node.is_directory,
                times: node.times.unwrap_or_default(),
                streams: streams(&node),
                names: node.names,
                path,
            })
            .collect();
        Self {
            files,
            problems: table.problems,
        }
    }
}

/// The record size of a loose `$MFT`: what its first record declares
/// (record 0, `$MFT` itself, or the next one when that one is damaged).
fn record_size(head: &[u8]) -> Option<usize> {
    (0..head.len()).step_by(MIN_RECORD_SIZE).find_map(|offset| {
        let size = super::record::declared_size(&head[offset..])?;
        let plausible = size.is_power_of_two()
            && (MIN_RECORD_SIZE..=MAX_RECORD_SIZE as usize).contains(&size)
            && offset % size == 0;
        plausible.then_some(size)
    })
}

fn streams(node: &Node) -> Vec<DataStream> {
    node.stream_names()
        .into_iter()
        .map(|name| DataStream {
            name: (!name.is_empty()).then(|| name.to_owned()),
            size: node.stream_size(name),
            resident: node.pieces(name).next().and_then(resident_value),
        })
        .collect()
}

fn resident_value(attribute: &Attribute) -> Option<Vec<u8>> {
    match &attribute.body {
        Body::Resident(bytes) => Some(bytes.clone()),
        Body::NonResident { .. } => None,
    }
}
