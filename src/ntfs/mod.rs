//! NTFS volumes, read from scratch: list allocated files (with alternate
//! data streams) and stream their content.
//!
//! The MFT is walked record by record, the way forensic MFT parsers do:
//! paths are rebuilt from each record's `$FILE_NAME` parent reference, and
//! attributes stored in extension records are merged into their base record.
//! Directory indexes are not needed.

mod boot;
mod reader;
mod record;
mod runs;

use std::cell::OnceCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Read, Seek};

use boot::Boot;
use reader::{Extents, StreamReader};
use record::{flags, kind, Attribute, Body, FileName, Record, DOS_NAMESPACE};

use crate::partition::read_at;
use crate::window::Window;

/// Record number of the root directory.
const ROOT_RECORD: u64 = 5;
/// Upper bound on records scanned (hostile MFT sizes).
const MAX_RECORDS: u64 = 64 * 1024 * 1024;
/// Upper bound on path depth (cycles in hostile parent references).
const MAX_DEPTH: usize = 256;
/// Where files whose parent is gone are placed, as The Sleuth Kit does.
const ORPHANS: &str = "$OrphanFiles";

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
    boot: Boot,
    start: u64,
    length: u64,
    mft: Extents,
    index: OnceCell<Index>,
}

/// The result of walking the MFT once.
struct Index {
    files: Vec<FileEntry>,
    streams: HashMap<(u64, String), Stream>,
}

#[derive(Debug, Clone)]
enum Stream {
    Resident(Vec<u8>),
    NonResident(Extents),
    Unsupported(&'static str),
}

impl NtfsVolume {
    /// Open the NTFS volume occupying `start..start + length` of `disk`.
    ///
    /// # Errors
    /// When the range doesn't hold a readable NTFS volume.
    pub fn open<R: Read + Seek>(disk: &mut R, start: u64, length: u64) -> io::Result<Self> {
        let mut volume = Window::new(disk, start, length);
        let boot = boot::parse(&read_at(&mut volume, 0, 512)?).map_err(invalid_data)?;
        let mft_offset = boot
            .mft_cluster
            .checked_mul(boot.cluster_size)
            .ok_or_else(|| corrupt("MFT location"))?;
        let mut first = read_at(&mut volume, mft_offset, boot.record_size as usize)?;
        let mft_record = record::parse(&mut first)
            .map_err(invalid_data)?
            .ok_or_else(|| corrupt("$MFT record"))?;
        let Stream::NonResident(mft) = stream_of(&[mft_record.attributes.as_slice()], "") else {
            return Err(corrupt("$MFT data"));
        };
        Ok(Self {
            boot,
            start,
            length,
            mft,
            index: OnceCell::new(),
        })
    }

    /// Every allocated file and alternate data stream, sorted by path.
    /// Directories themselves are not listed (their named streams are).
    ///
    /// # Errors
    /// On read errors or when the MFT can't be walked.
    pub fn files<R: Read + Seek>(&self, disk: &mut R) -> io::Result<Vec<FileEntry>> {
        Ok(self.index(disk)?.files.clone())
    }

    /// Stream the content of `entry` into `consume`.
    ///
    /// Sparse ranges read as zeros without touching the disk, so a hostile
    /// or sparse stream can yield an enormous amount of data: consumers must
    /// bound what they read (e.g. with [`Read::take`]).
    ///
    /// # Errors
    /// When the stream can't be read (including compressed or encrypted
    /// streams, not supported yet).
    pub fn read<R: Read + Seek>(
        &self,
        disk: &mut R,
        entry: &FileEntry,
        consume: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        let key = (entry.record, entry.stream.clone().unwrap_or_default());
        let stream = self
            .index(disk)?
            .streams
            .get(&key)
            .cloned()
            .ok_or_else(|| corrupt("no such stream"))?;
        match stream {
            Stream::Resident(bytes) => consume(&mut bytes.as_slice()),
            Stream::NonResident(extents) => {
                let mut volume = Window::new(disk, self.start, self.length);
                let mut reader = StreamReader::new(&mut volume, &extents, self.boot.cluster_size);
                consume(&mut reader)
            }
            Stream::Unsupported(what) => Err(io::Error::new(io::ErrorKind::Unsupported, what)),
        }
    }

    fn index<R: Read + Seek>(&self, disk: &mut R) -> io::Result<&Index> {
        if let Some(index) = self.index.get() {
            return Ok(index);
        }
        let index = self.scan(disk)?;
        Ok(self.index.get_or_init(|| index))
    }

    /// Walk the MFT once: collect in-use records, merge extension records,
    /// rebuild paths.
    fn scan<R: Read + Seek>(&self, disk: &mut R) -> io::Result<Index> {
        let mut volume = Window::new(disk, self.start, self.length);
        let mut mft = StreamReader::new(&mut volume, &self.mft, self.boot.cluster_size);
        let record_size = self.boot.record_size;
        let count = (self.mft.real_size / record_size).min(MAX_RECORDS);
        let mut nodes: BTreeMap<u64, Node> = BTreeMap::new();
        // Ordered maps keep merging deterministic (hard links across
        // extension records would otherwise pick names in random order).
        let mut extensions: BTreeMap<u64, Vec<Vec<Attribute>>> = BTreeMap::new();
        let mut buffer = vec![0u8; record_size as usize];
        for number in 0..count {
            mft.read_exact(&mut buffer)?;
            // Corrupt records (torn writes, bad structure) are skipped.
            let Ok(Some(record)) = record::parse(&mut buffer) else {
                continue;
            };
            if !record.in_use {
                continue;
            }
            match record.base {
                Some(base) => extensions.entry(base).or_default().push(record.attributes),
                None => {
                    nodes.insert(number, Node::from(record));
                }
            }
        }
        for (base, attribute_sets) in extensions {
            if let Some(node) = nodes.get_mut(&base) {
                for attributes in attribute_sets {
                    node.merge_extension(attributes);
                }
            }
        }
        Ok(build_index(&nodes))
    }
}

/// What the scan keeps of each in-use base record.
struct Node {
    sequence: u16,
    is_directory: bool,
    names: Vec<FileName>,
    /// Attribute lists: the base record's, then each extension record's.
    attribute_sets: Vec<Vec<Attribute>>,
}

impl From<Record> for Node {
    fn from(record: Record) -> Self {
        let mut node = Self {
            sequence: record.sequence,
            is_directory: record.is_directory,
            names: Vec::new(),
            attribute_sets: Vec::new(),
        };
        node.merge_extension(record.attributes);
        node
    }
}

impl Node {
    fn merge_extension(&mut self, attributes: Vec<Attribute>) {
        self.names.extend(
            attributes
                .iter()
                .filter(|a| a.kind == kind::FILE_NAME)
                .filter_map(|a| match &a.body {
                    Body::Resident(value) => record::file_name(value).ok(),
                    Body::NonResident { .. } => None,
                }),
        );
        self.attribute_sets.push(
            attributes
                .into_iter()
                .filter(|a| a.kind == kind::DATA)
                .collect(),
        );
    }

    /// The long name (8.3 aliases only as a last resort).
    fn primary_name(&self) -> Option<&FileName> {
        self.names
            .iter()
            .find(|n| n.namespace != DOS_NAMESPACE)
            .or_else(|| self.names.first())
    }

    fn stream_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .attribute_sets
            .iter()
            .flatten()
            .map(|a| a.name.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

fn build_index(nodes: &BTreeMap<u64, Node>) -> Index {
    let mut files = Vec::new();
    let mut streams = HashMap::new();
    for (&number, node) in nodes {
        if number == ROOT_RECORD {
            continue;
        }
        let Some(path) = path_of(nodes, number) else {
            continue;
        };
        for name in node.stream_names() {
            if node.is_directory && name.is_empty() {
                continue;
            }
            let sets: Vec<&[Attribute]> = node.attribute_sets.iter().map(Vec::as_slice).collect();
            let stream = stream_of(&sets, &name);
            let size = match &stream {
                Stream::Resident(bytes) => bytes.len() as u64,
                Stream::NonResident(extents) => extents.real_size,
                Stream::Unsupported(_) => declared_size(&sets, &name),
            };
            files.push(FileEntry {
                path: path.clone(),
                record: number,
                stream: (!name.is_empty()).then(|| name.clone()),
                size,
            });
            streams.insert((number, name), stream);
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.stream.cmp(&b.stream)));
    Index { files, streams }
}

/// The path of `number` from the root, or under [`ORPHANS`] when its parent
/// chain is broken (parent reused, gone, or cyclic).
fn path_of(nodes: &BTreeMap<u64, Node>, number: u64) -> Option<Vec<String>> {
    let mut components = Vec::new();
    let mut seen = HashSet::new();
    let mut current = number;
    while current != ROOT_RECORD {
        let name = nodes.get(&current)?.primary_name()?;
        components.push(name.name.clone());
        let parent_ok = nodes
            .get(&name.parent)
            .is_some_and(|p| p.is_directory && p.sequence == name.parent_sequence);
        if !parent_ok || !seen.insert(current) || components.len() > MAX_DEPTH {
            components.push(ORPHANS.to_owned());
            break;
        }
        current = name.parent;
    }
    components.reverse();
    Some(components)
}

/// Assemble the `$DATA` attribute named `name` from its pieces.
fn stream_of(sets: &[&[Attribute]], name: &str) -> Stream {
    let mut pieces: Vec<&Attribute> = sets
        .iter()
        .flat_map(|set| set.iter())
        .filter(|a| a.kind == kind::DATA && a.name == name)
        .collect();
    if pieces.iter().any(|a| a.flags & flags::ENCRYPTED != 0) {
        return Stream::Unsupported("encrypted (EFS) stream");
    }
    if pieces.iter().any(|a| a.flags & flags::COMPRESSED != 0) {
        return Stream::Unsupported("compressed stream");
    }
    if let Some(Body::Resident(bytes)) = pieces.first().map(|a| &a.body) {
        return Stream::Resident(bytes.clone());
    }
    pieces.sort_by_key(|a| match a.body {
        Body::NonResident { first_vcn, .. } => first_vcn,
        Body::Resident(_) => 0,
    });
    let mut extents = Extents {
        runs: Vec::new(),
        real_size: 0,
        initialized_size: 0,
    };
    for piece in pieces {
        if let Body::NonResident {
            first_vcn,
            runs,
            real_size,
            initialized_size,
        } = &piece.body
        {
            if *first_vcn == 0 {
                extents.real_size = *real_size;
                extents.initialized_size = *initialized_size;
            }
            extents.runs.extend_from_slice(runs);
        }
    }
    Stream::NonResident(extents)
}

fn declared_size(sets: &[&[Attribute]], name: &str) -> u64 {
    sets.iter()
        .flat_map(|set| set.iter())
        .filter(|a| a.kind == kind::DATA && a.name == name)
        .find_map(|a| match &a.body {
            Body::Resident(bytes) => Some(bytes.len() as u64),
            Body::NonResident {
                first_vcn: 0,
                real_size,
                ..
            } => Some(*real_size),
            Body::NonResident { .. } => None,
        })
        .unwrap_or(0)
}

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("corrupt NTFS structure: {what}"),
    )
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` adapter
fn invalid_data(error: common::bytes::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
