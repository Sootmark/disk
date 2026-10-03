//! NTFS volumes, read from scratch: list allocated files (with alternate
//! data streams) and stream their content; and loose `$MFT` files.
//!
//! The MFT is walked record by record, the way forensic MFT parsers do:
//! paths are rebuilt from each record's `$FILE_NAME` parent reference, and
//! attributes stored in extension records are merged into their base record.
//! Directory indexes are not needed.

mod boot;
mod lznt1;
mod mft;
mod reader;
mod record;
mod runs;
mod table;

use std::cell::OnceCell;
use std::collections::HashMap;
use std::io::{self, Read, Seek};

use boot::Boot;
use reader::{CompressedReader, Extents, StreamReader};
use record::{flags, kind, Attribute, Body};
use table::{Table, ROOT_RECORD};

pub use mft::{DataStream, FileName, Mft, MftFile, MftProblem, Namespace};

use crate::partition::read_at;
use crate::times::Times;
use crate::window::Window;

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
    /// The file's times (an alternate data stream has its file's).
    pub times: Times,
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
    /// LZNT1-compressed, in units of this many clusters.
    Compressed(Extents, u64),
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
        let default_data = mft_record
            .attributes
            .iter()
            .filter(|a| a.kind == kind::DATA && a.name.is_empty())
            .collect();
        let Stream::NonResident(mft) = stream_of(default_data) else {
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
    /// When the stream can't be read (including encrypted streams, not
    /// supported yet). Compressed streams (LZNT1) are decompressed.
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
            Stream::Compressed(extents, unit_clusters) => {
                let mut volume = Window::new(disk, self.start, self.length);
                let mut reader = CompressedReader::new(
                    &mut volume,
                    &extents,
                    self.boot.cluster_size,
                    unit_clusters,
                );
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

    /// Every file record of the volume's MFT, deleted ones included: what
    /// [`Mft::read`] gives for the volume's `$MFT` copied out.
    ///
    /// # Errors
    /// On read errors.
    pub fn mft<R: Read + Seek>(&self, disk: &mut R) -> io::Result<Mft> {
        Ok(Mft::from_table(self.table(disk)?))
    }

    /// Walk the MFT once.
    fn scan<R: Read + Seek>(&self, disk: &mut R) -> io::Result<Index> {
        Ok(build_index(&self.table(disk)?))
    }

    fn table<R: Read + Seek>(&self, disk: &mut R) -> io::Result<Table> {
        let mut volume = Window::new(disk, self.start, self.length);
        let mft = StreamReader::new(&mut volume, &self.mft, self.boot.cluster_size);
        Table::read(mft, self.boot.record_size as usize)
    }
}

/// The in-use files and their streams. Corrupt records are left out.
fn build_index(table: &Table) -> Index {
    let mut files = Vec::new();
    let mut streams = HashMap::new();
    for (&number, node) in table.nodes.iter().filter(|(_, node)| node.in_use) {
        if number == ROOT_RECORD {
            continue;
        }
        let Some(path) = table.path_of(number) else {
            continue;
        };
        for name in node.stream_names() {
            if node.is_directory && name.is_empty() {
                continue;
            }
            files.push(FileEntry {
                path: path.clone(),
                record: number,
                stream: (!name.is_empty()).then(|| name.to_owned()),
                size: node.stream_size(name),
                times: node.times.unwrap_or_default(),
            });
            streams.insert(
                (number, name.to_owned()),
                stream_of(node.pieces(name).collect()),
            );
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.stream.cmp(&b.stream)));
    Index { files, streams }
}

/// Assemble a `$DATA` stream from its pieces.
fn stream_of(mut pieces: Vec<&Attribute>) -> Stream {
    if pieces.iter().any(|a| a.flags & flags::ENCRYPTED != 0) {
        return Stream::Unsupported("encrypted (EFS) stream");
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
    let compressed = pieces.iter().any(|a| a.flags & flags::COMPRESSED != 0);
    let mut unit = 0;
    for piece in pieces {
        if let Body::NonResident {
            first_vcn,
            runs,
            real_size,
            initialized_size,
            compression_unit,
        } = &piece.body
        {
            if *first_vcn == 0 {
                extents.real_size = *real_size;
                extents.initialized_size = *initialized_size;
                if compressed {
                    unit = *compression_unit;
                }
            }
            extents.runs.extend_from_slice(runs);
        }
    }
    if !compressed {
        return Stream::NonResident(extents);
    }
    // The unit size is on the first piece: 16 clusters in practice.
    match unit {
        1..=8 => Stream::Compressed(extents, 1 << unit),
        _ => Stream::Unsupported("compressed stream with an unusual compression unit"),
    }
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
