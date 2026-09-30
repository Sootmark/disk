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

/// Reads an NTFS-compressed stream a compression unit at a time: a unit
/// with all its clusters allocated is stored as is, one with none reads
/// as zeros, and one whose allocated clusters end early holds LZNT1 data.
pub(crate) struct CompressedReader<'a, V> {
    volume: &'a mut V,
    extents: &'a Extents,
    cluster_size: u64,
    /// Clusters per compression unit.
    unit_clusters: u64,
    unit: Vec<u8>,
    /// Which unit `unit` holds.
    loaded: Option<u64>,
    position: u64,
}

impl<'a, V: Read + Seek> CompressedReader<'a, V> {
    pub(crate) fn new(
        volume: &'a mut V,
        extents: &'a Extents,
        cluster_size: u64,
        unit_clusters: u64,
    ) -> Self {
        Self {
            volume,
            extents,
            cluster_size,
            unit_clusters,
            unit: Vec::new(),
            loaded: None,
            position: 0,
        }
    }

    /// Where each cluster of unit `index` is on the volume (`None`: sparse).
    fn clusters(&self, index: u64) -> Vec<Option<u64>> {
        let first = index * self.unit_clusters;
        let mut out = Vec::with_capacity(self.unit_clusters as usize);
        let mut vcn = 0u64;
        for run in &self.extents.runs {
            let end = vcn.saturating_add(run.clusters);
            let from = first.max(vcn);
            let to = end.min(first + self.unit_clusters);
            for v in from..to {
                out.push(run.lcn.map(|lcn| lcn + (v - vcn)));
            }
            vcn = end;
            if vcn >= first + self.unit_clusters {
                break;
            }
        }
        out.resize(self.unit_clusters as usize, None);
        out
    }

    fn load(&mut self, index: u64) -> io::Result<()> {
        let unit_bytes = (self.unit_clusters * self.cluster_size) as usize;
        let clusters = self.clusters(index);
        let allocated: Vec<u64> = clusters.iter().map_while(|c| *c).collect();
        let mut raw = Vec::with_capacity(allocated.len() * self.cluster_size as usize);
        for lcn in &allocated {
            let at = lcn.checked_mul(self.cluster_size).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "cluster outside the volume")
            })?;
            let start = raw.len();
            raw.resize(start + self.cluster_size as usize, 0);
            self.volume.seek(SeekFrom::Start(at))?;
            self.volume.read_exact(&mut raw[start..])?;
        }
        self.unit = if allocated.len() == clusters.len() {
            raw
        } else if allocated.is_empty() {
            vec![0; unit_bytes]
        } else {
            let mut out = Vec::with_capacity(unit_bytes);
            super::lznt1::decompress(&raw, unit_bytes, &mut out)?;
            out.resize(unit_bytes, 0);
            out
        };
        self.loaded = Some(index);
        Ok(())
    }
}

impl<V: Read + Seek> Read for CompressedReader<'_, V> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.extents.real_size;
        if buf.is_empty() || self.position >= size {
            return Ok(0);
        }
        let unit_bytes = self.unit_clusters * self.cluster_size;
        let index = self.position / unit_bytes;
        if self.loaded != Some(index) {
            self.load(index)?;
        }
        let within = (self.position % unit_bytes) as usize;
        let available = (unit_bytes as usize - within).min((size - self.position) as usize);
        let n = buf.len().min(available);
        if self.position >= self.extents.initialized_size {
            buf[..n].fill(0);
        } else {
            buf[..n].copy_from_slice(&self.unit[within..within + n]);
        }
        self.position += n as u64;
        Ok(n)
    }
}
