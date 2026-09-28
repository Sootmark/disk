//! Partition tables: GPT and MBR (with extended partitions).

use std::collections::HashSet;
use std::io::{self, Read, Seek, SeekFrom};

/// Sector size assumed for partition tables.
pub const SECTOR_SIZE: u64 = 512;
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xaa];
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_ENTRIES_OFFSET: usize = 446;
const MBR_ENTRY_SIZE: usize = 16;
const MBR_ENTRY_COUNT: usize = 4;
const GPT_PROTECTIVE_TYPE: u8 = 0xee;
const EXTENDED_TYPES: [u8; 3] = [0x05, 0x0f, 0x85];
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// Upper bounds that stop hostile tables from causing huge reads.
const MAX_GPT_ENTRIES: u32 = 1024;
const MAX_GPT_ENTRY_SIZE: u32 = 4096;
const MIN_GPT_ENTRY_SIZE: u32 = 128;
const MAX_LOGICAL_PARTITIONS: usize = 128;
/// GPT partition names are 36 UTF-16 code units.
const GPT_NAME_OFFSET: usize = 56;
const GPT_NAME_LENGTH: usize = 72;

/// How the disk is partitioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// GUID Partition Table.
    Gpt,
    /// Master Boot Record.
    Mbr,
    /// No partition table: the disk is a single volume.
    None,
}

/// What a partition table says a partition is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionType {
    /// A GPT type GUID, e.g. `ebd0a0a2-b9e5-4433-87c0-68b6b72699c7` (basic data).
    Gpt(String),
    /// An MBR type byte, e.g. `0x07` (NTFS/exFAT).
    Mbr(u8),
    /// The whole disk, when there is no partition table.
    WholeDisk,
}

/// One partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// Position in the table (0-based; logical MBR partitions follow the primaries).
    pub slot: usize,
    /// Byte offset on the disk.
    pub offset: u64,
    /// Length in bytes.
    pub length: u64,
    /// The table's type for it.
    pub kind: PartitionType,
    /// GPT partition name, when set.
    pub name: Option<String>,
}

/// Read the partition table of a disk `disk_length` bytes long. A disk with
/// no recognisable table is returned as one whole-disk partition.
///
/// # Errors
/// On read errors. Malformed tables yield fewer partitions, not errors.
pub fn partitions<R: Read + Seek>(
    disk: &mut R,
    disk_length: u64,
) -> io::Result<(Scheme, Vec<Partition>)> {
    let mbr = read_at(disk, 0, SECTOR_SIZE as usize)?;
    let whole_disk = || {
        vec![Partition {
            slot: 0,
            offset: 0,
            length: disk_length,
            kind: PartitionType::WholeDisk,
            name: None,
        }]
    };
    if mbr.len() < SECTOR_SIZE as usize || mbr[MBR_SIGNATURE_OFFSET..] != MBR_SIGNATURE {
        return Ok((Scheme::None, whole_disk()));
    }
    let primaries = mbr_entries(&mbr);
    if primaries.iter().any(|e| e.type_byte == GPT_PROTECTIVE_TYPE) {
        let gpt = gpt_partitions(disk, disk_length)?;
        return Ok((Scheme::Gpt, gpt));
    }
    let mbr_partitions = mbr_partitions(disk, disk_length, &primaries)?;
    if mbr_partitions.is_empty() {
        // A boot sector with a signature but no entries: a partitionless volume.
        return Ok((Scheme::None, whole_disk()));
    }
    Ok((Scheme::Mbr, mbr_partitions))
}

#[derive(Debug, Clone, Copy)]
struct MbrEntry {
    type_byte: u8,
    start_sector: u64,
    sectors: u64,
}

fn mbr_entries(sector: &[u8]) -> Vec<MbrEntry> {
    (0..MBR_ENTRY_COUNT)
        .map(|i| {
            let e = &sector[MBR_ENTRIES_OFFSET + i * MBR_ENTRY_SIZE..][..MBR_ENTRY_SIZE];
            MbrEntry {
                type_byte: e[4],
                start_sector: u64::from(u32::from_le_bytes([e[8], e[9], e[10], e[11]])),
                sectors: u64::from(u32::from_le_bytes([e[12], e[13], e[14], e[15]])),
            }
        })
        .collect()
}

fn mbr_partitions<R: Read + Seek>(
    disk: &mut R,
    disk_length: u64,
    primaries: &[MbrEntry],
) -> io::Result<Vec<Partition>> {
    let mut partitions = Vec::new();
    for entry in primaries
        .iter()
        .filter(|e| !EXTENDED_TYPES.contains(&e.type_byte))
    {
        push_if_valid(&mut partitions, entry, 0, disk_length);
    }
    for extended in primaries
        .iter()
        .filter(|e| EXTENDED_TYPES.contains(&e.type_byte))
    {
        for logical in logical_partitions(disk, extended.start_sector)? {
            push_if_valid(
                &mut partitions,
                &logical.entry,
                logical.ebr_sector,
                disk_length,
            );
        }
    }
    Ok(partitions)
}

/// Add the partition `entry` describes (relative to `base_sector`) if it is
/// used, non-empty and inside the disk.
fn push_if_valid(
    partitions: &mut Vec<Partition>,
    entry: &MbrEntry,
    base_sector: u64,
    disk_length: u64,
) {
    let offset = (base_sector + entry.start_sector) * SECTOR_SIZE;
    let length = entry.sectors * SECTOR_SIZE;
    if entry.type_byte != 0 && entry.sectors > 0 && offset.saturating_add(length) <= disk_length {
        let slot = partitions.len();
        partitions.push(Partition {
            slot,
            offset,
            length,
            kind: PartitionType::Mbr(entry.type_byte),
            name: None,
        });
    }
}

struct Logical {
    ebr_sector: u64,
    entry: MbrEntry,
}

/// Follow the chain of extended boot records inside an extended partition.
fn logical_partitions<R: Read + Seek>(
    disk: &mut R,
    extended_start: u64,
) -> io::Result<Vec<Logical>> {
    let mut logicals = Vec::new();
    let mut visited = HashSet::new();
    let mut ebr_sector = extended_start;
    while logicals.len() < MAX_LOGICAL_PARTITIONS && visited.insert(ebr_sector) {
        let sector = read_at(disk, ebr_sector * SECTOR_SIZE, SECTOR_SIZE as usize)?;
        if sector.len() < SECTOR_SIZE as usize || sector[MBR_SIGNATURE_OFFSET..] != MBR_SIGNATURE {
            break;
        }
        let entries = mbr_entries(&sector);
        logicals.push(Logical {
            ebr_sector,
            entry: entries[0],
        });
        let next = entries[1];
        if next.type_byte == 0 || next.start_sector == 0 {
            break;
        }
        ebr_sector = extended_start + next.start_sector;
    }
    Ok(logicals)
}

fn gpt_partitions<R: Read + Seek>(disk: &mut R, disk_length: u64) -> io::Result<Vec<Partition>> {
    let header = read_at(disk, SECTOR_SIZE, SECTOR_SIZE as usize)?;
    if header.len() < 92 || &header[..8] != GPT_SIGNATURE {
        return Ok(Vec::new());
    }
    let entries_lba = u64::from_le_bytes(header[72..80].try_into().expect("8 bytes"));
    let count = u32::from_le_bytes(header[80..84].try_into().expect("4 bytes"));
    let entry_size = u32::from_le_bytes(header[84..88].try_into().expect("4 bytes"));
    let sane =
        count <= MAX_GPT_ENTRIES && (MIN_GPT_ENTRY_SIZE..=MAX_GPT_ENTRY_SIZE).contains(&entry_size);
    if !sane {
        return Ok(Vec::new());
    }
    let table = read_at(
        disk,
        entries_lba.saturating_mul(SECTOR_SIZE),
        (count * entry_size) as usize,
    )?;
    let partitions = table
        .chunks_exact(entry_size as usize)
        .enumerate()
        .filter(|(_, entry)| entry[..16].iter().any(|&b| b != 0))
        .filter_map(|(slot, entry)| {
            let first = u64::from_le_bytes(entry[32..40].try_into().expect("8 bytes"));
            let last = u64::from_le_bytes(entry[40..48].try_into().expect("8 bytes"));
            let offset = first.checked_mul(SECTOR_SIZE)?;
            let length = last
                .checked_sub(first)?
                .checked_add(1)?
                .checked_mul(SECTOR_SIZE)?;
            (offset.checked_add(length)? <= disk_length).then(|| Partition {
                slot,
                offset,
                length,
                kind: PartitionType::Gpt(format_guid(&entry[..16])),
                name: gpt_name(&entry[GPT_NAME_OFFSET..GPT_NAME_OFFSET + GPT_NAME_LENGTH]),
            })
        })
        .collect();
    Ok(partitions)
}

fn gpt_name(bytes: &[u8]) -> Option<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    let name = String::from_utf16_lossy(&units);
    (!name.is_empty()).then_some(name)
}

/// A GUID in its standard mixed-endian on-disk layout, lowercase.
fn format_guid(b: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    )
}

/// Read up to `len` bytes at `offset`; shorter at the end of the disk.
pub(crate) fn read_at<R: Read + Seek>(
    disk: &mut R,
    offset: u64,
    len: usize,
) -> io::Result<Vec<u8>> {
    disk.seek(SeekFrom::Start(offset))?;
    let mut buffer = Vec::with_capacity(len);
    disk.take(len as u64).read_to_end(&mut buffer)?;
    Ok(buffer)
}
