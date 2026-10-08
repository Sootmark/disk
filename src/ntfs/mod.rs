//! NTFS volumes, read from scratch: list allocated files (with alternate
//! data streams) and directory indexes, and stream their content; and loose
//! `$MFT` files.
//!
//! The MFT is walked record by record, the way forensic MFT parsers do:
//! paths are rebuilt from each record's `$FILE_NAME` parent reference, and
//! attributes stored in extension records are merged into their base record.
//! Directory indexes are not needed for that: they are only read as
//! streams of their own.

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
use record::{flags, kind, Attribute, Body, DIRECTORY_INDEX};
use table::{Table, ROOT_RECORD};

pub use mft::{DataStream, FileName, Mft, MftFile, MftProblem, Namespace};

use crate::partition::read_at;
use crate::times::Times;
use crate::window::Window;

/// One file, one alternate data stream of a file, or one directory's index
/// (NTFS) or entries (FAT, exFAT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Path components from the volume root (of the directory, for its
    /// index or entries: empty for the root's).
    pub path: Vec<String>,
    /// MFT record number; on a FAT or exFAT volume, the entry's index in
    /// its listing.
    pub record: u64,
    /// Alternate data stream name, or `None` for the default stream; for a
    /// directory index, the index's name (`$I30`); for a FAT or exFAT
    /// directory, its [`DirectoryFormat`](crate::DirectoryFormat)'s stream.
    pub stream: Option<String>,
    /// Which attribute the bytes come from.
    pub kind: StreamKind,
    /// Declared size of the stream in bytes. Sparse streams (such as
    /// `$UsnJrnl:$J`) legitimately declare far more than they store, and a
    /// corrupt record can declare anything: bound what you read.
    pub size: u64,
    /// The file's times (an alternate data stream has its file's).
    pub times: Times,
}

/// Which attribute a [`FileEntry`]'s bytes come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamKind {
    /// `$DATA`: a file's content, or an alternate data stream.
    Data,
    /// `$INDEX_ALLOCATION`: a directory's index, as INDX blocks (see
    /// [`NtfsVolume::directory_indexes`]).
    DirectoryIndex,
    /// A FAT or exFAT directory's entries, as its clusters store them (see
    /// [`FatVolume::directories`](crate::FatVolume::directories)).
    Directory,
}

impl FileEntry {
    /// The path joined with `\`, the way Windows writes it: with `:stream`
    /// appended for alternate data streams, `:$I30:$INDEX_ALLOCATION` for
    /// a directory index, and the stream as a last component for a FAT or
    /// exFAT directory (`Folder\$FAT_DIRECTORY`).
    #[must_use]
    pub fn display_path(&self) -> String {
        let path = self.path.join("\\");
        match (&self.stream, self.kind) {
            (Some(stream), StreamKind::Data) => format!("{path}:{stream}"),
            (Some(stream), StreamKind::DirectoryIndex) => {
                format!("{path}:{stream}:$INDEX_ALLOCATION")
            }
            (Some(stream), StreamKind::Directory) if path.is_empty() => stream.clone(),
            (Some(stream), StreamKind::Directory) => format!("{path}\\{stream}"),
            (None, _) => path,
        }
    }

    /// What the volume's index finds the entry's stream by.
    fn key(&self) -> StreamKey {
        (
            self.record,
            self.kind,
            self.stream.clone().unwrap_or_default(),
        )
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
    directory_indexes: Vec<FileEntry>,
    streams: HashMap<StreamKey, Stream>,
}

/// A stream's record number, kind and name (`""`: the default stream).
type StreamKey = (u64, StreamKind, String);

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
    /// Directories themselves are not listed (their named streams are, and
    /// their indexes by [`directory_indexes`](Self::directory_indexes)).
    ///
    /// # Errors
    /// On read errors or when the MFT can't be walked.
    pub fn files<R: Read + Seek>(&self, disk: &mut R) -> io::Result<Vec<FileEntry>> {
        Ok(self.index(disk)?.files.clone())
    }

    /// Every allocated directory's index (`$INDEX_ALLOCATION:$I30`) that
    /// outgrew its MFT record, the root's included, sorted by path. A
    /// directory whose index fits in its record (`$INDEX_ROOT` only) has
    /// none.
    ///
    /// [`read`](Self::read) gives the INDX blocks as stored, update
    /// sequence fixups not applied, as The Sleuth Kit's `icat` does: index
    /// parsers verify them. Entries since removed from the directory
    /// linger in the blocks' slack.
    ///
    /// # Errors
    /// On read errors or when the MFT can't be walked.
    pub fn directory_indexes<R: Read + Seek>(&self, disk: &mut R) -> io::Result<Vec<FileEntry>> {
        Ok(self.index(disk)?.directory_indexes.clone())
    }

    /// Stream the content of `entry` (a file, a stream or a directory
    /// index) into `consume`.
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
        let stream = self
            .index(disk)?
            .streams
            .get(&entry.key())
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

/// The in-use files, directory indexes and their streams. Corrupt records
/// are left out.
fn build_index(table: &Table) -> Index {
    let mut index = Index {
        files: Vec::new(),
        directory_indexes: Vec::new(),
        streams: HashMap::new(),
    };
    for (&number, node) in table.nodes.iter().filter(|(_, node)| node.in_use) {
        let Some(path) = table.path_of(number) else {
            continue;
        };
        let entry = |kind, name: &str, size| FileEntry {
            path: path.clone(),
            record: number,
            stream: (!name.is_empty()).then(|| name.to_owned()),
            kind,
            size,
            times: node.times.unwrap_or_default(),
        };
        if number != ROOT_RECORD {
            for name in node.stream_names() {
                if node.is_directory && name.is_empty() {
                    continue;
                }
                let file = entry(StreamKind::Data, name, node.stream_size(name));
                index
                    .streams
                    .insert(file.key(), stream_of(node.pieces(name).collect()));
                index.files.push(file);
            }
        }
        let size = node.index_size();
        if node.is_directory && size > 0 {
            let directory_index = entry(StreamKind::DirectoryIndex, DIRECTORY_INDEX, size);
            index.streams.insert(
                directory_index.key(),
                stream_of(node.index.iter().collect()),
            );
            index.directory_indexes.push(directory_index);
        }
    }
    index
        .files
        .sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.stream.cmp(&b.stream)));
    index.directory_indexes.sort_by(|a, b| a.path.cmp(&b.path));
    index
}

/// Assemble a stream (`$DATA`, or a directory's index allocation) from its
/// pieces.
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
