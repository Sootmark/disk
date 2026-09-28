//! Raw images split into numbered segments (`image.001`, `image.002`, …).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// The segments of a split raw image, read as one continuous disk.
pub struct SplitImage {
    segments: Vec<(File, u64)>,
    length: u64,
    position: u64,
}

impl SplitImage {
    /// Open `first` (ending in `.001`) and every following numbered segment.
    /// A path without a numeric extension is opened as a single segment.
    ///
    /// # Errors
    /// When a segment can't be opened.
    pub fn open(first: &Path) -> io::Result<Self> {
        let mut segments = Vec::new();
        for path in segment_paths(first) {
            let file = File::open(&path)?;
            let length = file.metadata()?.len();
            segments.push((file, length));
        }
        let length = segments.iter().map(|(_, len)| len).sum();
        Ok(Self {
            segments,
            length,
            position: 0,
        })
    }

    /// Total length in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.length
    }

    /// Whether the image is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// `first` and its existing successors: `x.001`, `x.002`, … until a gap.
fn segment_paths(first: &Path) -> Vec<PathBuf> {
    let Some(extension) = first.extension().and_then(|e| e.to_str()) else {
        return vec![first.to_owned()];
    };
    let Ok(start) = extension.parse::<u32>() else {
        return vec![first.to_owned()];
    };
    let width = extension.len();
    let last = 10u32.saturating_pow(width as u32).saturating_sub(1);
    (start..=last)
        .map(|n| first.with_extension(format!("{n:0width$}")))
        .take_while(|path| path.exists())
        .collect()
}

impl Read for SplitImage {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut segment_start = 0;
        for (file, length) in &mut self.segments {
            let segment_end = segment_start + *length;
            if self.position < segment_end {
                let within = self.position - segment_start;
                let wanted = buf
                    .len()
                    .min(usize::try_from(segment_end - self.position).unwrap_or(usize::MAX));
                file.seek(SeekFrom::Start(within))?;
                let read = file.read(&mut buf[..wanted])?;
                self.position += read as u64;
                return Ok(read);
            }
            segment_start = segment_end;
        }
        Ok(0)
    }
}

impl Seek for SplitImage {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let position = match target {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.length.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        self.position = position.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "seek before start of image")
        })?;
        Ok(self.position)
    }
}
