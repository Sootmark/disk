//! FAT12, FAT16, FAT32 and exFAT volumes: every allocated file, listed
//! from the directory tree and read through its cluster chain. Written
//! from Microsoft's specifications ("FAT: General Overview of On-Disk
//! Format", the exFAT file system specification).
//!
//! FAT directories hold 32-byte entries: an 8.3 name, attributes, the
//! first cluster and the size, preceded by long-name entries (UTF-16, 13
//! characters each) when the name needs one. exFAT directories hold entry
//! sets: a File entry, a Stream Extension (first cluster, sizes, whether
//! the clusters are contiguous and need no FAT) and File Name entries.
//! Deleted entries aren't listed. Every chain is bounded by the volume's
//! cluster count, so a looping FAT ends a file early instead of hanging.
//!
//! Times are MS-DOS date and time words: wall-clock, to 2 seconds, with a
//! 10 ms refinement for creation (and exFAT's modification), and a date
//! alone for FAT's last access. exFAT adds a UTC offset to each.

use std::collections::HashSet;
use std::io::{self, Read, Seek, SeekFrom};

use common::time::{Precision, Ts, TICKS_PER_SECOND};

use crate::ntfs::{FileEntry, StreamKind};
use crate::times::{known, Times};
use crate::window::Window;

/// Clusters 0 and 1 are reserved; data starts at cluster 2.
const FIRST_CLUSTER: u32 = 2;
const ENTRY: usize = 32;
/// Directory nesting beyond this is damage, not data.
const MAX_DEPTH: usize = 64;
/// Directory entries per volume beyond this are damage, not data.
const MAX_ENTRIES: usize = 10_000_000;
/// The largest directory either format allows (exFAT's 256 MiB).
const MAX_DIRECTORY: u64 = 256 << 20;

const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_LONG_NAME: u8 = 0x0f;
const DELETED: u8 = 0xe5;

const EXFAT_FILE: u8 = 0x85;
const EXFAT_STREAM: u8 = 0xc0;
const EXFAT_NAME: u8 = 0xc1;
/// Stream Extension flag: the clusters are contiguous, the FAT unused.
const EXFAT_NO_FAT_CHAIN: u8 = 0x02;
/// UTC offset flag: the low 7 bits are a signed count of 15 minutes.
const EXFAT_OFFSET_VALID: u8 = 0x80;

/// 100 ns ticks in 10 ms.
const CENTISECOND: i64 = TICKS_PER_SECOND / 100;
/// The largest valid 10 ms count (1.99 seconds).
const MAX_CENTISECONDS: u8 = 199;

fn corrupt(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    bytes
        .get(at..at + 2)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    bytes
        .get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

/// Which FAT a volume uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatKind {
    /// 12-bit FAT entries.
    Fat12,
    /// 16-bit FAT entries.
    Fat16,
    /// 32-bit FAT entries (28 used).
    Fat32,
    /// exFAT.
    ExFat,
}

/// Where a file's content is.
#[derive(Debug, Clone, Copy)]
struct Extent {
    first_cluster: u32,
    /// Bytes of content.
    size: u64,
    /// Bytes written; past this, zeros (exFAT's valid data length).
    valid: u64,
    /// The clusters follow each other, without the FAT (exFAT).
    contiguous: bool,
}

/// A FAT or exFAT volume at a byte range of a disk.
#[derive(Debug)]
pub struct FatVolume {
    kind: FatKind,
    start: u64,
    length: u64,
    cluster_size: u64,
    /// Byte offset of the first FAT in the volume.
    fat_offset: u64,
    /// Byte offset of cluster 2.
    data_offset: u64,
    cluster_count: u32,
    /// FAT12/16: the fixed root directory region, `(offset, bytes)`.
    fixed_root: Option<(u64, u64)>,
    root_cluster: u32,
    /// Every allocated file, and where its content is (same order).
    files: Vec<(FileEntry, Extent)>,
}

impl FatVolume {
    /// Open the FAT or exFAT volume occupying `start..start + length` of
    /// `disk`, and list its files.
    ///
    /// # Errors
    /// When the range doesn't hold a readable FAT or exFAT volume.
    pub fn open<R: Read + Seek>(disk: &mut R, start: u64, length: u64) -> io::Result<Self> {
        let mut boot = [0u8; 512];
        Window::new(disk, start, length).read_exact(&mut boot)?;
        let mut volume = if &boot[3..11] == b"EXFAT   " {
            Self::exfat(&boot, start, length)?
        } else {
            Self::fat(&boot, start, length)?
        };
        // No more clusters than the volume's length holds, whatever the
        // boot sector says.
        let fits = length.saturating_sub(volume.data_offset) / volume.cluster_size;
        volume.cluster_count = volume
            .cluster_count
            .min(u32::try_from(fits).unwrap_or(u32::MAX));
        volume.files = volume.list(disk)?;
        Ok(volume)
    }

    fn fat(boot: &[u8], start: u64, length: u64) -> io::Result<Self> {
        let bytes_per_sector = u64::from(u16_at(boot, 11));
        let sectors_per_cluster = u64::from(boot[13]);
        let reserved = u64::from(u16_at(boot, 14));
        let fats = u64::from(boot[16]);
        let root_entries = u64::from(u16_at(boot, 17));
        let total = match u16_at(boot, 19) {
            0 => u64::from(u32_at(boot, 32)),
            n => u64::from(n),
        };
        let fat16_sectors = u16_at(boot, 22);
        let fat_sectors = match fat16_sectors {
            0 => u64::from(u32_at(boot, 36)),
            n => u64::from(n),
        };
        let valid = matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
            && sectors_per_cluster.is_power_of_two()
            && reserved > 0
            && fats > 0
            && fat_sectors > 0;
        if !valid {
            return Err(corrupt("not a FAT boot sector"));
        }
        let root_sectors = (root_entries * ENTRY as u64).div_ceil(bytes_per_sector);
        let data_sector = reserved + fats * fat_sectors + root_sectors;
        let cluster_count = total.saturating_sub(data_sector) / sectors_per_cluster;
        // FAT32's boot sector leaves the 16-bit FAT size at 0 (small FAT32
        // volumes exist: Linux writes and reads them); otherwise the
        // cluster count decides between FAT12 and FAT16, as the
        // specification says.
        let kind = match (fat16_sectors, cluster_count) {
            (0, _) => FatKind::Fat32,
            (_, 0..=4084) => FatKind::Fat12,
            (_, 4085..=65_524) => FatKind::Fat16,
            _ => FatKind::Fat32,
        };
        let fixed_root = (kind != FatKind::Fat32).then(|| {
            (
                (reserved + fats * fat_sectors) * bytes_per_sector,
                root_sectors * bytes_per_sector,
            )
        });
        Ok(Self {
            kind,
            start,
            length,
            cluster_size: bytes_per_sector * sectors_per_cluster,
            fat_offset: reserved * bytes_per_sector,
            data_offset: data_sector * bytes_per_sector,
            cluster_count: u32::try_from(cluster_count).unwrap_or(u32::MAX),
            fixed_root,
            root_cluster: if kind == FatKind::Fat32 {
                u32_at(boot, 44)
            } else {
                0
            },
            files: Vec::new(),
        })
    }

    fn exfat(boot: &[u8], start: u64, length: u64) -> io::Result<Self> {
        let sector_shift = u32::from(boot[108]);
        let cluster_shift = u32::from(boot[109]);
        if !(9..=12).contains(&sector_shift) || sector_shift + cluster_shift > 25 {
            return Err(corrupt("not an exFAT boot sector"));
        }
        let sector = 1u64 << sector_shift;
        Ok(Self {
            kind: FatKind::ExFat,
            start,
            length,
            cluster_size: sector << cluster_shift,
            fat_offset: u64::from(u32_at(boot, 80)) * sector,
            data_offset: u64::from(u32_at(boot, 88)) * sector,
            cluster_count: u32_at(boot, 92),
            fixed_root: None,
            root_cluster: u32_at(boot, 96),
            files: Vec::new(),
        })
    }

    /// Which FAT the volume uses.
    #[must_use]
    pub fn kind(&self) -> FatKind {
        self.kind
    }

    /// Every allocated file, sorted by path. Directories themselves aren't
    /// listed; `record` is the file's index in this listing.
    #[must_use]
    pub fn files(&self) -> Vec<FileEntry> {
        self.files.iter().map(|(entry, _)| entry.clone()).collect()
    }

    /// Stream the content of `entry` into `consume`.
    ///
    /// # Errors
    /// When the entry isn't one of this volume's, or its clusters can't be
    /// read (a chain ending early, a cluster outside the volume).
    pub fn read<R: Read + Seek>(
        &self,
        disk: &mut R,
        entry: &FileEntry,
        consume: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        let (_, extent) = usize::try_from(entry.record)
            .ok()
            .and_then(|i| self.files.get(i))
            .ok_or_else(|| corrupt("no such file on this volume"))?;
        let clusters = self.chain(disk, extent.first_cluster, extent.contiguous, extent.size)?;
        let mut volume = Window::new(disk, self.start, self.length);
        let mut reader = ChainReader {
            volume: &mut volume,
            clusters,
            cluster_size: self.cluster_size,
            data_offset: self.data_offset,
            size: extent.size,
            valid: extent.valid,
            position: 0,
        };
        consume(&mut reader)
    }

    /// The clusters of a chain starting at `first`, enough for `size`
    /// bytes (a chain ending early is an error).
    fn chain<R: Read + Seek>(
        &self,
        disk: &mut R,
        first: u32,
        contiguous: bool,
        size: u64,
    ) -> io::Result<Vec<u32>> {
        let needed = size.div_ceil(self.cluster_size);
        if needed == 0 {
            return Ok(Vec::new());
        }
        if !self.is_data_cluster(first) {
            return Err(corrupt(format!("first cluster {first} outside the volume")));
        }
        if contiguous {
            let last = u64::from(first) + needed - 1;
            if last >= u64::from(self.cluster_count) + u64::from(FIRST_CLUSTER) {
                return Err(corrupt("contiguous clusters run past the volume"));
            }
            return Ok((0..needed).map(|i| first + i as u32).collect());
        }
        let mut clusters = Vec::with_capacity(needed.min(1 << 20) as usize);
        let mut seen = HashSet::new();
        let mut current = first;
        while (clusters.len() as u64) < needed {
            if !self.is_data_cluster(current) || !seen.insert(current) {
                return Err(corrupt(format!(
                    "cluster chain ends after {} of {needed} clusters",
                    clusters.len()
                )));
            }
            clusters.push(current);
            current = self.next(disk, current)?;
        }
        Ok(clusters)
    }

    fn is_data_cluster(&self, cluster: u32) -> bool {
        cluster >= FIRST_CLUSTER && cluster - FIRST_CLUSTER < self.cluster_count
    }

    /// The FAT entry of `cluster`: the next one in its chain.
    fn next<R: Read + Seek>(&self, disk: &mut R, cluster: u32) -> io::Result<u32> {
        let mut volume = Window::new(disk, self.start, self.length);
        let (at, width) = match self.kind {
            FatKind::Fat12 => (u64::from(cluster) * 3 / 2, 2),
            FatKind::Fat16 => (u64::from(cluster) * 2, 2),
            FatKind::Fat32 | FatKind::ExFat => (u64::from(cluster) * 4, 4),
        };
        volume.seek(SeekFrom::Start(self.fat_offset + at))?;
        let mut bytes = [0u8; 4];
        volume.read_exact(&mut bytes[..width])?;
        let value = u32::from_le_bytes(bytes);
        Ok(match self.kind {
            FatKind::Fat12 if cluster & 1 == 1 => value >> 4,
            FatKind::Fat12 => value & 0x0fff,
            FatKind::Fat16 => value & 0xffff,
            FatKind::Fat32 => value & 0x0fff_ffff,
            FatKind::ExFat => value,
        })
    }

    /// The bytes of a directory: the fixed root region, or its clusters.
    fn directory<R: Read + Seek>(
        &self,
        disk: &mut R,
        first: u32,
        contiguous: bool,
        size: Option<u64>,
    ) -> io::Result<Vec<u8>> {
        if first == 0 {
            if let Some((offset, bytes)) = self.fixed_root {
                let mut data = vec![0; bytes as usize];
                let mut volume = Window::new(disk, self.start, self.length);
                volume.seek(SeekFrom::Start(offset))?;
                volume.read_exact(&mut data)?;
                return Ok(data);
            }
        }
        // FAT directories have no size: follow the chain to its end.
        let size = size
            .unwrap_or(u64::from(self.cluster_count) * self.cluster_size)
            .min(MAX_DIRECTORY);
        let clusters = match self.chain(disk, first, contiguous, size) {
            Ok(clusters) => clusters,
            Err(_) if !contiguous => self.whole_chain(disk, first)?,
            Err(e) => return Err(e),
        };
        let mut data = Vec::with_capacity(clusters.len() * self.cluster_size as usize);
        let mut volume = Window::new(disk, self.start, self.length);
        for cluster in clusters {
            let at = self.data_offset + u64::from(cluster - FIRST_CLUSTER) * self.cluster_size;
            let from = data.len();
            data.resize(from + self.cluster_size as usize, 0);
            volume.seek(SeekFrom::Start(at))?;
            volume.read_exact(&mut data[from..])?;
        }
        Ok(data)
    }

    /// Every cluster of a chain, to its end mark.
    fn whole_chain<R: Read + Seek>(&self, disk: &mut R, first: u32) -> io::Result<Vec<u32>> {
        let mut clusters = Vec::new();
        let mut seen = HashSet::new();
        let mut current = first;
        let limit = (MAX_DIRECTORY / self.cluster_size) as usize;
        while self.is_data_cluster(current) && seen.insert(current) && clusters.len() < limit {
            clusters.push(current);
            current = self.next(disk, current)?;
        }
        Ok(clusters)
    }

    /// Walk the directory tree from the root.
    fn list<R: Read + Seek>(&self, disk: &mut R) -> io::Result<Vec<(FileEntry, Extent)>> {
        let mut files = Vec::new();
        let mut entries = 0;
        // The root has no recorded size in either variant: its chain ends it.
        let root = (self.root_cluster, false, None);
        let mut pending = vec![(Vec::<String>::new(), root)];
        let mut visited = HashSet::new();
        while let Some((path, (first, contiguous, size))) = pending.pop() {
            if path.len() > MAX_DEPTH || (first != 0 && !visited.insert(first)) {
                continue;
            }
            let Ok(bytes) = self.directory(disk, first, contiguous, size) else {
                continue;
            };
            let children = match self.kind {
                FatKind::ExFat => exfat_entries(&bytes),
                _ => fat_entries(&bytes),
            };
            for child in children {
                entries += 1;
                if entries > MAX_ENTRIES {
                    return Err(corrupt("more directory entries than a volume holds"));
                }
                let mut child_path = path.clone();
                child_path.push(child.name);
                if child.directory {
                    let size = (self.kind == FatKind::ExFat).then_some(child.extent.size);
                    pending.push((
                        child_path,
                        (child.extent.first_cluster, child.extent.contiguous, size),
                    ));
                } else {
                    files.push((
                        FileEntry {
                            path: child_path,
                            record: 0,
                            stream: None,
                            kind: StreamKind::Data,
                            size: child.extent.size,
                            times: child.times,
                        },
                        child.extent,
                    ));
                }
            }
        }
        files.sort_by(|a, b| a.0.path.cmp(&b.0.path));
        for (index, (entry, _)) in files.iter_mut().enumerate() {
            entry.record = index as u64;
        }
        Ok(files)
    }
}

/// A directory entry, decoded.
struct Child {
    name: String,
    directory: bool,
    extent: Extent,
    times: Times,
}

/// The allocated entries of a FAT directory, long names applied.
fn fat_entries(bytes: &[u8]) -> Vec<Child> {
    let mut out = Vec::new();
    let mut long: Vec<(u8, Vec<u16>)> = Vec::new();
    for entry in bytes.chunks_exact(ENTRY) {
        match entry[0] {
            0 => break,
            DELETED => {
                long.clear();
                continue;
            }
            _ => {}
        }
        let attributes = entry[11];
        if attributes & 0x3f == ATTR_LONG_NAME {
            let units: Vec<u16> = [1..11, 14..26, 28..32]
                .into_iter()
                .flat_map(|r| {
                    entry[r]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>()
                })
                .collect();
            long.push((entry[0] & 0x1f, units));
            continue;
        }
        let short = short_name(entry);
        if attributes & ATTR_VOLUME_ID != 0 || short == "." || short == ".." {
            long.clear();
            continue;
        }
        let name = long_name(&mut long).unwrap_or(short);
        let first_cluster = u32::from(u16_at(entry, 20)) << 16 | u32::from(u16_at(entry, 26));
        let size = u64::from(u32_at(entry, 28));
        out.push(Child {
            name,
            directory: attributes & ATTR_DIRECTORY != 0,
            extent: Extent {
                first_cluster,
                size,
                valid: size,
                contiguous: false,
            },
            times: fat_times(entry),
        });
    }
    out
}

/// The long name the preceding entries spell, when they do: pieces in
/// reverse order, numbered from 1, up to a NUL or 0xFFFF padding.
fn long_name(long: &mut Vec<(u8, Vec<u16>)>) -> Option<String> {
    let mut pieces = std::mem::take(long);
    if pieces.is_empty() {
        return None;
    }
    pieces.sort_by_key(|(order, _)| *order);
    let ordered = pieces
        .iter()
        .enumerate()
        .all(|(i, (order, _))| usize::from(*order) == i + 1);
    if !ordered {
        return None;
    }
    let units: Vec<u16> = pieces
        .into_iter()
        .flat_map(|(_, units)| units)
        .take_while(|&u| u != 0 && u != 0xffff)
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// `NAME.EXT` from an 8.3 entry (0x05 standing for a leading 0xE5).
fn short_name(entry: &[u8]) -> String {
    let mut base: Vec<u8> = entry[0..8].to_vec();
    if base[0] == 0x05 {
        base[0] = DELETED;
    }
    let base = String::from_utf8_lossy(&base).trim_end().to_owned();
    let extension = String::from_utf8_lossy(&entry[8..11]).trim_end().to_owned();
    if extension.is_empty() {
        base
    } else {
        format!("{base}.{extension}")
    }
}

/// The in-use file entry sets of an exFAT directory.
fn exfat_entries(bytes: &[u8]) -> Vec<Child> {
    let mut out = Vec::new();
    let entries: Vec<&[u8]> = bytes.chunks_exact(ENTRY).collect();
    let mut i = 0;
    while i < entries.len() {
        let entry = entries[i];
        if entry[0] == 0 {
            break;
        }
        if entry[0] != EXFAT_FILE {
            i += 1;
            continue;
        }
        let secondaries = usize::from(entry[1]);
        let set = &entries[i + 1..(i + 1 + secondaries).min(entries.len())];
        i += 1 + secondaries;
        let Some(stream) = set.first().filter(|s| s[0] == EXFAT_STREAM) else {
            continue;
        };
        let name_length = usize::from(stream[3]);
        let units: Vec<u16> = set[1..]
            .iter()
            .filter(|e| e[0] == EXFAT_NAME)
            .flat_map(|e| {
                e[2..32]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
            })
            .take(name_length)
            .collect();
        let size = u64_at(stream, 24);
        out.push(Child {
            name: String::from_utf16_lossy(&units),
            directory: u16_at(entry, 4) & u16::from(ATTR_DIRECTORY) != 0,
            extent: Extent {
                first_cluster: u32_at(stream, 20),
                size,
                valid: u64_at(stream, 8).min(size),
                contiguous: stream[1] & EXFAT_NO_FAT_CHAIN != 0,
            },
            times: exfat_times(entry),
        });
    }
    out
}

/// The times of a FAT directory entry, all wall-clock.
fn fat_times(entry: &[u8]) -> Times {
    let accessed = Ts::from_dos(u16_at(entry, 18), 0)
        .ticks()
        .map(|midnight| Ts::from_local_ticks(midnight, Precision::Day));
    Times {
        created: plus_centiseconds(dos(u16_at(entry, 16), u16_at(entry, 14)), entry[13]),
        modified: dos(u16_at(entry, 24), u16_at(entry, 22)),
        changed: None,
        accessed,
    }
}

/// The times of an exFAT File entry: date and time words (the time in the
/// low half), each with a UTC offset.
fn exfat_times(entry: &[u8]) -> Times {
    let stamp = |at| dos(u16_at(entry, at + 2), u16_at(entry, at));
    Times {
        created: in_utc(plus_centiseconds(stamp(8), entry[20]), entry[22]),
        modified: in_utc(plus_centiseconds(stamp(12), entry[21]), entry[23]),
        changed: None,
        accessed: in_utc(stamp(16), entry[24]),
    }
}

/// A date and time word pair, when it holds a time.
fn dos(date: u16, time: u16) -> Option<Ts> {
    known(Ts::from_dos(date, time))
}

/// `local` refined by a count of 10 ms. `common` has no 10 ms precision:
/// milliseconds is the closest.
fn plus_centiseconds(local: Option<Ts>, count: u8) -> Option<Ts> {
    if count > MAX_CENTISECONDS {
        return None;
    }
    let ticks = local?.ticks()? + i64::from(count) * CENTISECOND;
    Some(Ts::from_local_ticks(ticks, Precision::Millisecond))
}

/// `local` in UTC when the exFAT offset byte says how; otherwise as is,
/// its zone unknown.
fn in_utc(local: Option<Ts>, offset: u8) -> Option<Ts> {
    if offset & EXFAT_OFFSET_VALID == 0 {
        return local;
    }
    // Sign-extend the 7-bit count of quarter hours.
    let quarter_hours = i32::from((offset << 1) as i8 >> 1);
    known(local?.assume_offset(quarter_hours * 15))
}

/// Reads a file's clusters in chain order.
struct ChainReader<'a, V> {
    volume: &'a mut V,
    clusters: Vec<u32>,
    cluster_size: u64,
    data_offset: u64,
    size: u64,
    valid: u64,
    position: u64,
}

impl<V: Read + Seek> Read for ChainReader<'_, V> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.size {
            return Ok(0);
        }
        let index = (self.position / self.cluster_size) as usize;
        let within = self.position % self.cluster_size;
        let available = (self.cluster_size - within).min(self.size - self.position);
        let n = buf.len().min(available as usize);
        if self.position >= self.valid {
            buf[..n].fill(0);
        } else {
            let n = n.min((self.valid - self.position) as usize);
            let cluster = self.clusters[index];
            let at =
                self.data_offset + u64::from(cluster - FIRST_CLUSTER) * self.cluster_size + within;
            self.volume.seek(SeekFrom::Start(at))?;
            self.volume.read_exact(&mut buf[..n])?;
            self.position += n as u64;
            return Ok(n);
        }
        self.position += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn dos_date(year: u16, month: u16, day: u16) -> u16 {
        ((year - 1980) << 9) | (month << 5) | day
    }

    const fn dos_time(hour: u16, minute: u16, second: u16) -> u16 {
        (hour << 11) | (minute << 5) | (second / 2)
    }

    const DATE: u16 = dos_date(2020, 1, 1);
    const TIME: u16 = dos_time(12, 30, 58);

    fn iso(time: Option<Ts>) -> Option<String> {
        time?.to_iso8601()
    }

    #[test]
    fn zero_and_impossible_fat_times_are_none() {
        let mut entry = [0u8; ENTRY];
        assert_eq!(fat_times(&entry), Times::default());
        entry[13] = 200; // past 1.99 s
        entry[14..16].copy_from_slice(&TIME.to_le_bytes());
        entry[16..18].copy_from_slice(&DATE.to_le_bytes());
        entry[24..26].copy_from_slice(&dos_date(2020, 2, 30).to_le_bytes());
        assert_eq!(fat_times(&entry), Times::default());
        entry[13] = 199;
        assert_eq!(
            iso(fat_times(&entry).created).as_deref(),
            Some("2020-01-01T12:30:59.9900000")
        );
    }

    #[test]
    fn exfat_offsets_are_signed_quarter_hours() {
        let local = dos(DATE, TIME);
        let utc = |offset| iso(in_utc(local, offset));
        // +01:00, -00:15, -16:00, then an offset not marked valid.
        assert_eq!(
            utc(0x80 | 4).as_deref(),
            Some("2020-01-01T11:30:58.0000000Z")
        );
        assert_eq!(
            utc(0x80 | 0x7f).as_deref(),
            Some("2020-01-01T12:45:58.0000000Z")
        );
        assert_eq!(
            utc(0x80 | 0x40).as_deref(),
            Some("2020-01-02T04:30:58.0000000Z")
        );
        assert_eq!(utc(0x04).as_deref(), Some("2020-01-01T12:30:58.0000000"));
        assert_eq!(in_utc(None, 0x84), None);
    }
}
