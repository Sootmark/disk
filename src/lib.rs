//! Disk images for forensic intake.
//!
//! - [`SplitImage`]: raw images, whole or split into numbered segments.
//! - [`partitions`]: GPT and MBR tables (extended partitions included).
//! - [`identify`]: which file system a partition holds.
//! - [`NtfsVolume`]: list allocated files and alternate data streams, and
//!   stream their content without extracting anything.
//! - [`FatVolume`]: the same for FAT12, FAT16, FAT32 and exFAT.
//! - [`Times`]: each listed file's times, UTC or wall-clock as stored.
//!
//! Everything works on any `Read + Seek` disk, so other container formats
//! (VHDX, E01) plug in by providing one.

mod fat;
mod filesystem;
mod ntfs;
mod partition;
mod split;
mod times;
mod window;

pub use fat::{FatKind, FatVolume};
pub use filesystem::{identify, Filesystem};
pub use ntfs::{FileEntry, NtfsVolume};
pub use partition::{partitions, Partition, PartitionType, Scheme, SECTOR_SIZE};
pub use split::SplitImage;
pub use times::Times;
pub use window::Window;
