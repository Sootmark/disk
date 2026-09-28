//! Disk images for forensic intake.
//!
//! - [`SplitImage`]: raw images, whole or split into numbered segments.
//! - [`partitions`]: GPT and MBR tables (extended partitions included).
//! - [`identify`]: which file system a partition holds.
//! - [`NtfsVolume`]: list allocated files and alternate data streams, and
//!   stream their content without extracting anything.
//!
//! Everything works on any `Read + Seek` disk, so other container formats
//! (VHDX, E01) plug in by providing one.

mod filesystem;
mod ntfs;
mod partition;
mod split;
mod window;

pub use filesystem::{identify, Filesystem};
pub use ntfs::{FileEntry, NtfsVolume};
pub use partition::{partitions, Partition, PartitionType, Scheme, SECTOR_SIZE};
pub use split::SplitImage;
pub use window::Window;
