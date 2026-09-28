//! The NTFS boot sector: geometry and where the MFT starts.

use common::bytes::{Error, ErrorKind, Reader, Result};

const OEM_ID: &[u8; 8] = b"NTFS    ";
const OEM_OFFSET: usize = 3;
const GEOMETRY_OFFSET: usize = 0x0b;
const TOTAL_SECTORS_OFFSET: usize = 0x28;
/// Upper bounds that reject nonsense geometry from hostile images.
const MAX_CLUSTER_SIZE: u64 = 2 << 20;
const MAX_RECORD_SIZE: u64 = 64 * 1024;

/// Geometry read from the boot sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Boot {
    pub(crate) bytes_per_sector: u64,
    pub(crate) cluster_size: u64,
    pub(crate) mft_cluster: u64,
    pub(crate) record_size: u64,
    pub(crate) volume_size: u64,
}

pub(crate) fn parse(sector: &[u8]) -> Result<Boot> {
    let mut r = Reader::new(sector);
    r.seek(OEM_OFFSET)?;
    if r.array::<8>()? != *OEM_ID {
        return Err(invalid(OEM_OFFSET, "an NTFS boot sector"));
    }
    r.seek(GEOMETRY_OFFSET)?;
    let bytes_per_sector = u64::from(r.u16_le()?);
    let sectors_per_cluster = sectors_per_cluster(r.u8()?);
    r.seek(TOTAL_SECTORS_OFFSET)?;
    let total_sectors = r.u64_le()?;
    let mft_cluster = r.u64_le()?;
    r.skip(8)?; // MFT mirror cluster
    let clusters_per_record = r.u8()? as i8;
    let cluster_size = bytes_per_sector * sectors_per_cluster;
    let record_size = size_from_clusters(clusters_per_record, cluster_size);
    let sane = matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        && cluster_size.is_power_of_two()
        && cluster_size <= MAX_CLUSTER_SIZE
        && record_size.is_power_of_two()
        && (bytes_per_sector..=MAX_RECORD_SIZE).contains(&record_size);
    if !sane {
        return Err(invalid(GEOMETRY_OFFSET, "plausible NTFS geometry"));
    }
    Ok(Boot {
        bytes_per_sector,
        cluster_size,
        mft_cluster,
        record_size,
        volume_size: total_sectors.saturating_mul(bytes_per_sector),
    })
}

/// Values above 0x80 encode a power of two: 2^(256 - value).
fn sectors_per_cluster(raw: u8) -> u64 {
    if raw > 0x80 {
        1u64.checked_shl(256 - u32::from(raw)).unwrap_or(0)
    } else {
        u64::from(raw)
    }
}

/// A positive count is in clusters; a negative one means 2^(-value) bytes.
fn size_from_clusters(raw: i8, cluster_size: u64) -> u64 {
    if raw < 0 {
        1u64.checked_shl(u32::from(raw.unsigned_abs())).unwrap_or(0)
    } else {
        u64::from(raw.unsigned_abs()) * cluster_size
    }
}

fn invalid(offset: usize, expected: &'static str) -> Error {
    Error {
        offset,
        kind: ErrorKind::Invalid { expected },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_encoded_sizes() {
        assert_eq!(sectors_per_cluster(8), 8);
        assert_eq!(sectors_per_cluster(0xf4), 1 << 12);
        assert_eq!(size_from_clusters(-10, 4096), 1024);
        assert_eq!(size_from_clusters(1, 4096), 4096);
    }
}
