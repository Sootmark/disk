//! Identifying the file system on a partition.

use std::io::{self, Read, Seek};

use crate::partition::{read_at, Partition, SECTOR_SIZE};

/// The file system found on a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filesystem {
    /// NTFS.
    Ntfs,
    /// FAT12, FAT16 or FAT32.
    Fat,
    /// exFAT.
    ExFat,
    /// Not recognised (empty, encrypted, or unsupported).
    Unknown,
}

/// OEM identifiers at offset 3 of the boot sector.
const NTFS_OEM: &[u8] = b"NTFS    ";
const EXFAT_OEM: &[u8] = b"EXFAT   ";
/// FAT type strings in the boot sector (FAT12/16 at 54, FAT32 at 82).
const FAT16_TYPE_OFFSET: usize = 54;
const FAT32_TYPE_OFFSET: usize = 82;

/// Identify the file system of `partition` from its boot sector.
///
/// # Errors
/// On read errors.
pub fn identify<R: Read + Seek>(disk: &mut R, partition: &Partition) -> io::Result<Filesystem> {
    let boot = read_at(disk, partition.offset, SECTOR_SIZE as usize)?;
    let at = |offset: usize, expected: &[u8]| {
        boot.get(offset..offset + expected.len()) == Some(expected)
    };
    let is_fat = at(FAT16_TYPE_OFFSET, b"FAT") || at(FAT32_TYPE_OFFSET, b"FAT32");
    Ok(if at(3, NTFS_OEM) {
        Filesystem::Ntfs
    } else if at(3, EXFAT_OEM) {
        Filesystem::ExFat
    } else if is_fat {
        Filesystem::Fat
    } else {
        Filesystem::Unknown
    })
}
