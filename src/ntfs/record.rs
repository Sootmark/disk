//! MFT file records: fixups and attributes.

use common::bytes::{Error, ErrorKind, Reader, Result};
use common::text;
use common::time::Ts;

use super::mft::{FileName, Namespace};
use super::runs::{self, Run};
use crate::times::{known, Times};

const FILE_SIGNATURE: &[u8; 4] = b"FILE";
/// What Windows writes over a record whose fixups failed.
const BAD_SIGNATURE: &[u8; 4] = b"BAAD";
const ALLOCATED_SIZE_OFFSET: usize = 0x1c;
/// Fixups protect the last two bytes of every 512-byte stride.
const FIXUP_STRIDE: usize = 512;
const IN_USE: u16 = 0x0001;
const DIRECTORY: u16 = 0x0002;
const END_OF_ATTRIBUTES: u32 = 0xffff_ffff;
/// Record numbers are 48 bits of a 64-bit file reference.
const RECORD_NUMBER_MASK: u64 = 0x0000_ffff_ffff_ffff;

/// Attribute type codes used here.
pub(crate) mod kind {
    pub(crate) const STANDARD_INFORMATION: u32 = 0x10;
    pub(crate) const FILE_NAME: u32 = 0x30;
    pub(crate) const DATA: u32 = 0x80;
    pub(crate) const INDEX_ALLOCATION: u32 = 0xa0;
}

/// The name of a directory's index of file names.
pub(crate) const DIRECTORY_INDEX: &str = "$I30";

/// Attribute flags.
pub(crate) mod flags {
    pub(crate) const COMPRESSED: u16 = 0x0001;
    pub(crate) const ENCRYPTED: u16 = 0x4000;
}

/// A parsed MFT record.
#[derive(Debug, Clone)]
pub(crate) struct Record {
    pub(crate) in_use: bool,
    pub(crate) is_directory: bool,
    pub(crate) sequence: u16,
    /// For extension records, the base record they belong to: its record
    /// number and sequence number.
    pub(crate) base: Option<(u64, u16)>,
    pub(crate) attributes: Vec<Attribute>,
}

/// One attribute of a record.
#[derive(Debug, Clone)]
pub(crate) struct Attribute {
    pub(crate) kind: u32,
    pub(crate) name: String,
    pub(crate) flags: u16,
    pub(crate) body: Body,
}

/// Where an attribute's value is.
#[derive(Debug, Clone)]
pub(crate) enum Body {
    /// Stored inside the record.
    Resident(Vec<u8>),
    /// Stored in clusters, described by runs (one piece of possibly several,
    /// covering virtual clusters `first_vcn..`).
    NonResident {
        first_vcn: u64,
        runs: Vec<Run>,
        real_size: u64,
        initialized_size: u64,
        /// Clusters per compression unit, as a power of two (0: none).
        compression_unit: u16,
    },
}

/// The record number part of a 64-bit file reference.
pub(crate) const fn record_number(reference: u64) -> u64 {
    reference & RECORD_NUMBER_MASK
}

/// The sequence number part of a 64-bit file reference.
pub(crate) const fn reference_sequence(reference: u64) -> u16 {
    (reference >> 48) as u16
}

/// The size a record declares for itself (its allocated size), when
/// `bytes` starts with one.
pub(crate) fn declared_size(bytes: &[u8]) -> Option<usize> {
    if bytes.get(..4) != Some(FILE_SIGNATURE.as_slice()) {
        return None;
    }
    let mut r = Reader::new(bytes);
    r.seek(ALLOCATED_SIZE_OFFSET).ok()?;
    r.u32_le().ok().map(|size| size as usize)
}

/// Parse a record in place (fixups are applied to `buffer`). `Ok(None)` for
/// slots that don't hold a record (never used, or zeroed).
pub(crate) fn parse(buffer: &mut [u8]) -> Result<Option<Record>> {
    match buffer.get(..4) {
        Some(signature) if signature == FILE_SIGNATURE => {}
        Some(signature) if signature == BAD_SIGNATURE => {
            return Err(invalid(0, "a record Windows didn't mark bad (BAAD)"));
        }
        _ => return Ok(None),
    }
    apply_fixups(buffer)?;
    let mut r = Reader::new(buffer);
    r.seek(0x10)?;
    let sequence = r.u16_le()?;
    r.skip(2)?; // hard link count
    let first_attribute = usize::from(r.u16_le()?);
    let record_flags = r.u16_le()?;
    let used_size = (r.u32_le()? as usize).min(buffer.len());
    r.skip(4)?; // allocated size
    let base_reference = r.u64_le()?;
    let attributes = parse_attributes(&buffer[..used_size], first_attribute)?;
    Ok(Some(Record {
        in_use: record_flags & IN_USE != 0,
        is_directory: record_flags & DIRECTORY != 0,
        sequence,
        base: (base_reference != 0).then(|| {
            (
                record_number(base_reference),
                reference_sequence(base_reference),
            )
        }),
        attributes,
    }))
}

/// Check the update sequence number at the end of every stride and restore
/// the original bytes. A mismatch means a torn write: the record is corrupt.
fn apply_fixups(buffer: &mut [u8]) -> Result<()> {
    let mut r = Reader::new(buffer);
    r.seek(4)?;
    let array_offset = usize::from(r.u16_le()?);
    let count = usize::from(r.u16_le()?);
    let strides = buffer.len() / FIXUP_STRIDE;
    if count == 0 || count - 1 > strides {
        return Err(invalid(4, "a fixup array matching the record size"));
    }
    let array = buffer
        .get(array_offset..array_offset + count * 2)
        .ok_or(invalid(4, "a fixup array inside the record"))?
        .to_vec();
    let marker = [array[0], array[1]];
    for (stride, original) in array[2..].chunks_exact(2).enumerate() {
        let end = (stride + 1) * FIXUP_STRIDE;
        if buffer[end - 2..end] != marker {
            return Err(invalid(end - 2, "an intact sector (torn write)"));
        }
        buffer[end - 2..end].copy_from_slice(original);
    }
    Ok(())
}

fn parse_attributes(used: &[u8], first: usize) -> Result<Vec<Attribute>> {
    let mut attributes = Vec::new();
    let mut offset = first;
    loop {
        let mut r = Reader::new(used);
        r.seek(offset)?;
        let kind = r.u32_le()?;
        if kind == END_OF_ATTRIBUTES {
            return Ok(attributes);
        }
        let length = r.u32_le()? as usize;
        let end = offset
            .checked_add(length)
            .filter(|&end| length >= 16 && end <= used.len())
            .ok_or(invalid(offset, "an attribute inside the record"))?;
        attributes.push(parse_attribute(&used[offset..end], kind)?);
        offset = end;
    }
}

fn parse_attribute(bytes: &[u8], kind: u32) -> Result<Attribute> {
    let mut r = Reader::new(bytes);
    r.seek(8)?;
    let non_resident = r.u8()? != 0;
    let name_length = usize::from(r.u8()?);
    let name_offset = usize::from(r.u16_le()?);
    let flags = r.u16_le()?;
    let name_bytes = bytes
        .get(name_offset..name_offset + name_length * 2)
        .ok_or(invalid(name_offset, "an attribute name"))?;
    let name = text::utf16le(name_bytes).text;
    r.seek(16)?;
    let body = if non_resident {
        let first_vcn = r.u64_le()?;
        r.skip(8)?; // last VCN
        let runs_offset = usize::from(r.u16_le()?);
        let compression_unit = r.u16_le()?;
        r.skip(4 + 8)?; // padding, allocated size
        let real_size = r.u64_le()?;
        let initialized_size = r.u64_le()?;
        let runs = runs::decode(
            bytes
                .get(runs_offset..)
                .ok_or(invalid(runs_offset, "a run list"))?,
        )?;
        Body::NonResident {
            first_vcn,
            runs,
            real_size,
            initialized_size,
            compression_unit,
        }
    } else {
        let length = r.u32_le()? as usize;
        let value_offset = usize::from(r.u16_le()?);
        let value = bytes
            .get(value_offset..value_offset + length)
            .ok_or(invalid(value_offset, "a resident value"))?;
        Body::Resident(value.to_vec())
    };
    Ok(Attribute {
        kind,
        name,
        flags,
        body,
    })
}

fn invalid(offset: usize, expected: &'static str) -> Error {
    Error {
        offset,
        kind: ErrorKind::Invalid { expected },
    }
}

const FILE_NAME_LENGTH_OFFSET: usize = 0x40;

/// A `$FILE_NAME` value: the parent reference, four times, two sizes, then
/// the name.
pub(crate) fn file_name(value: &[u8]) -> Result<FileName> {
    let mut r = Reader::new(value);
    let parent_reference = r.u64_le()?;
    let times = filetimes(&mut r)?;
    let allocated_size = r.u64_le()?;
    let size = r.u64_le()?;
    r.seek(FILE_NAME_LENGTH_OFFSET)?;
    let length = usize::from(r.u8()?);
    let namespace = Namespace::from_code(r.u8()?);
    let name = text::utf16le(r.bytes(length * 2)?).text;
    Ok(FileName {
        name,
        namespace,
        parent: record_number(parent_reference),
        parent_sequence: reference_sequence(parent_reference),
        times,
        allocated_size,
        size,
    })
}

/// The times of a `$STANDARD_INFORMATION` value.
pub(crate) fn standard_information(value: &[u8]) -> Result<Times> {
    filetimes(&mut Reader::new(value))
}

/// Four FILETIMEs in a row: created, modified, MFT entry changed, accessed.
fn filetimes(r: &mut Reader) -> Result<Times> {
    let mut next = || {
        r.u64_le()
            .map(|filetime| known(Ts::from_filetime(filetime)))
    };
    Ok(Times {
        created: next()?,
        modified: next()?,
        changed: next()?,
        accessed: next()?,
    })
}
