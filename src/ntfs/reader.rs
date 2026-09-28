//! Reading a non-resident stream through its runs.

use std::io::{self, Read, Seek, SeekFrom};

use super::runs::Run;

/// A non-resident stream: runs in virtual-cluster order, with its sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Extents {
    pub(crate) runs: Vec<Run>,
    pub(crate) real_size: u64,
    /// Bytes past this offset were never written and read as zeros.
    pub(crate) initialized_size: u64,
}

/// Reads a non-resident stream from a volume.
pub(crate) struct StreamReader<'a, V> {
    volume: &'a mut V,
    extents: &'a Extents,
    cluster_size: u64,
    /// First virtual cluster of each run, for lookups.
    run_starts: Vec<u64>,
    position: u64,
}

impl<'a, V: Read + Seek> StreamReader<'a, V> {
    pub(crate) fn new(volume: &'a mut V, extents: &'a Extents, cluster_size: u64) -> Self {
        let run_starts = extents
            .runs
            .iter()
            .scan(0u64, |vcn, run| {
                let start = *vcn;
                *vcn = vcn.saturating_add(run.clusters);
                Some(start)
            })
            .collect();
        Self {
            volume,
            extents,
            cluster_size,
            run_starts,
            position: 0,
        }
    }
}

impl<V: Read + Seek> Read for StreamReader<'_, V> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.extents.real_size;
        if buf.is_empty() || self.position >= size {
            return Ok(0);
        }
        let vcn = self.position / self.cluster_size;
        let index = self
            .run_starts
            .partition_point(|&start| start <= vcn)
            .saturating_sub(1);
        let run = self.extents.runs.get(index).copied();
        let Some(run) = run.filter(|run| vcn < self.run_starts[index].saturating_add(run.clusters))
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream shorter than its declared size",
            ));
        };
        let run_end = self.run_starts[index]
            .saturating_add(run.clusters)
            .saturating_mul(self.cluster_size);
        let mut end = run_end.min(size);
        let initialized = self.extents.initialized_size;
        if self.position < initialized {
            end = end.min(initialized);
        }
        let wanted = buf
            .len()
            .min(usize::try_from(end - self.position).unwrap_or(usize::MAX));
        let buf = &mut buf[..wanted];
        match run.lcn {
            Some(lcn) if self.position < initialized => {
                let run_start = self.run_starts[index].saturating_mul(self.cluster_size);
                let at = lcn
                    .checked_mul(self.cluster_size)
                    .and_then(|offset| offset.checked_add(self.position - run_start))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "cluster outside the volume")
                    })?;
                self.volume.seek(SeekFrom::Start(at))?;
                self.volume.read_exact(buf)?;
            }
            _ => buf.fill(0), // sparse, or past the initialized size
        }
        self.position += wanted as u64;
        Ok(wanted)
    }
}
