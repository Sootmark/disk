//! A read-only view of a byte range of a larger reader.

use std::io::{self, Read, Seek, SeekFrom};

/// Exposes `start..start + len` of `inner` as a stream of its own, so a
/// partition can be read as if it were the whole device.
pub struct Window<'r, R> {
    inner: &'r mut R,
    start: u64,
    len: u64,
    position: u64,
}

impl<'r, R: Seek> Window<'r, R> {
    /// A view of `len` bytes of `inner` starting at `start`.
    pub fn new(inner: &'r mut R, start: u64, len: u64) -> Self {
        Self {
            inner,
            start,
            len,
            position: 0,
        }
    }
}

impl<R: Read + Seek> Read for Window<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.len.saturating_sub(self.position);
        let wanted = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if wanted == 0 {
            return Ok(0);
        }
        self.inner
            .seek(SeekFrom::Start(self.start + self.position))?;
        let read = self.inner.read(&mut buf[..wanted])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl<R: Seek> Seek for Window<'_, R> {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let position = match target {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        let position = position.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "seek before start of window")
        })?;
        self.position = position;
        Ok(position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_only_inside_the_window() {
        let mut data = Cursor::new((0u8..100).collect::<Vec<_>>());
        let mut window = Window::new(&mut data, 10, 5);
        let mut out = Vec::new();
        window.read_to_end(&mut out).unwrap();
        assert_eq!(out, vec![10, 11, 12, 13, 14]);
    }

    #[test]
    fn seeks_relative_to_the_window() {
        let mut data = Cursor::new((0u8..100).collect::<Vec<_>>());
        let mut window = Window::new(&mut data, 10, 5);
        window.seek(SeekFrom::End(-1)).unwrap();
        let mut byte = [0u8; 1];
        window.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [14]);
        assert!(window.seek(SeekFrom::Current(-10)).is_err());
    }
}
