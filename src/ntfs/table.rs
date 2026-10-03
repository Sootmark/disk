//! The MFT as a table of files: each base record merged with its extension
//! records, and paths rebuilt from `$FILE_NAME` parent references. Shared
//! by volumes and loose `$MFT` files.

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Read};

use super::mft::{FileName, MftProblem};
use super::record::{self, kind, Attribute, Body, Record};
use crate::times::Times;

/// Record number of the root directory.
pub(crate) const ROOT_RECORD: u64 = 5;
/// Upper bound on records read (hostile MFT sizes).
const MAX_RECORDS: u64 = 64 * 1024 * 1024;
/// Upper bound on path depth (cycles in hostile parent references).
const MAX_DEPTH: usize = 256;
/// Where files whose parent is gone are placed, as The Sleuth Kit does.
pub(crate) const ORPHANS: &str = "$OrphanFiles";

/// Every base record of an MFT, in use or not, by record number.
pub(crate) struct Table {
    /// Ordered, so merging and listing are deterministic.
    pub(crate) nodes: BTreeMap<u64, Node>,
    pub(crate) problems: Vec<MftProblem>,
}

/// What the table keeps of a base record and its extension records.
pub(crate) struct Node {
    pub(crate) in_use: bool,
    pub(crate) is_directory: bool,
    pub(crate) sequence: u16,
    /// From `$STANDARD_INFORMATION`, when the record has a readable one.
    pub(crate) times: Option<Times>,
    pub(crate) names: Vec<FileName>,
    /// `$DATA` attributes: the base record's, then its extension records'.
    pub(crate) data: Vec<Attribute>,
}

impl Table {
    /// Read the records of an MFT, `record_size` bytes each, until its end.
    /// Damaged records are skipped and reported in `problems`.
    ///
    /// Extension records are merged into their base record by the base
    /// reference each one carries, so `$ATTRIBUTE_LIST` isn't needed (a
    /// loose `$MFT` couldn't read a non-resident one anyway).
    pub(crate) fn read<R: Read>(mut mft: R, record_size: usize) -> io::Result<Self> {
        let mut table = Self {
            nodes: BTreeMap::new(),
            problems: Vec::new(),
        };
        let mut extensions = Vec::new();
        let mut buffer = vec![0u8; record_size];
        for number in 0.. {
            if number == MAX_RECORDS {
                table.report(number, format!("not read: more than {MAX_RECORDS} records"));
                break;
            }
            match fill(&mut mft, &mut buffer)? {
                0 => break,
                read if read < record_size => {
                    table.report(number, format!("truncated: {read} of {record_size} bytes"));
                    break;
                }
                _ => {}
            }
            match record::parse(&mut buffer) {
                Ok(None) => {}
                Ok(Some(record)) => {
                    if let Some(base) = record.base {
                        extensions.push((number, base, record));
                    } else {
                        let node = Node::new(number, record, &mut table.problems);
                        table.nodes.insert(number, node);
                    }
                }
                Err(error) => table.report(number, error.to_string()),
            }
        }
        for (number, (base, sequence), extension) in extensions {
            // A stale extension record (its base freed or reused since)
            // describes another file, or none: it is left out.
            match table.nodes.get_mut(&base) {
                Some(node) if node.in_use == extension.in_use && node.is_referred(sequence) => {
                    node.absorb(number, extension.attributes, &mut table.problems);
                }
                _ => {}
            }
        }
        Ok(table)
    }

    /// The path of `number` from the root (empty for the root itself), or
    /// `None` when the record has no name. A file whose parent chain is
    /// broken (a parent freed and reused, missing, or cyclic) is placed
    /// under [`ORPHANS`], below as much of the chain as is known.
    pub(crate) fn path_of(&self, number: u64) -> Option<Vec<String>> {
        if number == ROOT_RECORD {
            return Some(Vec::new());
        }
        let mut name = self.nodes.get(&number)?.primary_name()?;
        let mut components = vec![name.name.clone()];
        let mut seen = HashSet::from([number]);
        let complete = loop {
            let Some(parent) = self.parent(name) else {
                break false;
            };
            if name.parent == ROOT_RECORD {
                break true;
            }
            let fresh = seen.insert(name.parent) && components.len() < MAX_DEPTH;
            let Some(next) = parent.primary_name().filter(|_| fresh) else {
                break false;
            };
            components.push(next.name.clone());
            name = next;
        };
        if !complete {
            components.push(ORPHANS.to_owned());
        }
        components.reverse();
        Some(components)
    }

    /// The directory `name` was created in, if its record still is that
    /// directory.
    fn parent(&self, name: &FileName) -> Option<&Node> {
        self.nodes
            .get(&name.parent)
            .filter(|parent| parent.is_directory && parent.is_referred(name.parent_sequence))
    }

    fn report(&mut self, record: u64, message: String) {
        self.problems.push(MftProblem {
            record: Some(record),
            message,
        });
    }
}

impl Node {
    fn new(number: u64, record: Record, problems: &mut Vec<MftProblem>) -> Self {
        let mut node = Self {
            in_use: record.in_use,
            is_directory: record.is_directory,
            sequence: record.sequence,
            times: None,
            names: Vec::new(),
            data: Vec::new(),
        };
        node.absorb(number, record.attributes, problems);
        node
    }

    /// Take in the attributes of record `number`: the base record, or one of
    /// its extension records.
    fn absorb(&mut self, number: u64, attributes: Vec<Attribute>, problems: &mut Vec<MftProblem>) {
        for attribute in attributes {
            if attribute.kind == kind::DATA {
                self.data.push(attribute);
                continue;
            }
            // `$STANDARD_INFORMATION` and `$FILE_NAME` are always resident.
            let Body::Resident(value) = &attribute.body else {
                continue;
            };
            let (label, parsed) = match attribute.kind {
                kind::STANDARD_INFORMATION => (
                    "$STANDARD_INFORMATION",
                    record::standard_information(value).map(|times| {
                        self.times.get_or_insert(times);
                    }),
                ),
                kind::FILE_NAME => (
                    "$FILE_NAME",
                    record::file_name(value).map(|name| self.names.push(name)),
                ),
                _ => continue,
            };
            if let Err(error) = parsed {
                problems.push(MftProblem {
                    record: Some(number),
                    message: format!("unreadable {label}: {error}"),
                });
            }
        }
    }

    /// Whether a reference carrying `sequence` still points at this record:
    /// the sequence numbers match, or the record was freed since (freeing
    /// increments it, skipping zero), so its last file is the one meant.
    fn is_referred(&self, sequence: u16) -> bool {
        let freed_since = !self.in_use && self.sequence == sequence.checked_add(1).unwrap_or(1);
        self.sequence == sequence || freed_since
    }

    /// The name paths are built from: a Windows long name, else a POSIX
    /// one, else whatever there is (8.3 aliases last).
    pub(crate) fn primary_name(&self) -> Option<&FileName> {
        self.names.iter().min_by_key(|n| n.namespace.rank())
    }

    /// Names of the `$DATA` streams, sorted (`""`: the default stream).
    pub(crate) fn stream_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.data.iter().map(|a| a.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    /// The pieces of stream `name`, in record order.
    pub(crate) fn pieces<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Attribute> {
        self.data.iter().filter(move |a| a.name == name)
    }

    /// The size stream `name` declares: its resident value's length, or the
    /// real size on its first non-resident piece.
    pub(crate) fn stream_size(&self, name: &str) -> u64 {
        self.pieces(name)
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
}

/// Read until `buffer` is full or the input ends; how many bytes were read.
fn fill<R: Read>(input: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match input.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}
