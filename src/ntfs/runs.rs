//! Data runs: where a non-resident attribute's clusters live.

use common::bytes::{Error, ErrorKind, Reader, Result};

/// A contiguous range of clusters, or a sparse hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Run {
    /// Length in clusters.
    pub(crate) clusters: u64,
    /// First logical cluster on the volume, or `None` for a sparse hole.
    pub(crate) lcn: Option<u64>,
}

/// Decode a run list. Each run starts with a header byte: the low nibble is
/// the size of the length field, the high nibble the size of the (signed,
/// relative) cluster offset field; an offset size of 0 means a sparse hole.
pub(crate) fn decode(bytes: &[u8]) -> Result<Vec<Run>> {
    let mut r = Reader::new(bytes);
    let mut runs = Vec::new();
    let mut lcn: i64 = 0;
    while r.remaining() > 0 {
        let header = r.u8()?;
        if header == 0 {
            break;
        }
        let (length_size, offset_size) = (usize::from(header & 0x0f), usize::from(header >> 4));
        if length_size == 0 || length_size > 8 || offset_size > 8 {
            return Err(Error {
                offset: r.offset() - 1,
                kind: ErrorKind::Invalid {
                    expected: "a valid run header",
                },
            });
        }
        let clusters = unsigned(r.bytes(length_size)?);
        let run_lcn = if offset_size == 0 {
            None
        } else {
            lcn = lcn
                .checked_add(signed(r.bytes(offset_size)?))
                .filter(|&l| l >= 0)
                .ok_or(Error {
                    offset: r.offset(),
                    kind: ErrorKind::Invalid {
                        expected: "a cluster number on the volume",
                    },
                })?;
            Some(lcn as u64)
        };
        runs.push(Run {
            clusters,
            lcn: run_lcn,
        });
    }
    Ok(runs)
}

fn unsigned(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, &b| (value << 8) | u64::from(b))
}

/// Little-endian two's complement of any width up to 8 bytes.
fn signed(bytes: &[u8]) -> i64 {
    let value = unsigned(bytes);
    let shift = 64 - 8 * bytes.len() as u32;
    ((value << shift) as i64) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_relative_and_sparse_runs() {
        // 0x18 clusters at LCN 0x5634; 0x10 sparse; 0x20 clusters at 0x5634 - 0x34.
        let bytes = [0x21, 0x18, 0x34, 0x56, 0x01, 0x10, 0x11, 0x20, 0xcc, 0x00];
        let runs = decode(&bytes).unwrap();
        assert_eq!(
            runs,
            [
                Run {
                    clusters: 0x18,
                    lcn: Some(0x5634)
                },
                Run {
                    clusters: 0x10,
                    lcn: None
                },
                Run {
                    clusters: 0x20,
                    lcn: Some(0x5634 - 0x34)
                },
            ]
        );
    }

    #[test]
    fn rejects_runs_before_the_volume() {
        assert!(decode(&[0x11, 0x01, 0xff, 0x00]).is_err());
    }
}
