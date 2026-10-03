//! File times, common to every file system.

use common::time::Ts;

/// When a file was created, modified, changed and accessed. A time is
/// `None` when the file system doesn't keep it, or the stored value is zero
/// or impossible.
///
/// NTFS times are UTC, from `$STANDARD_INFORMATION` (what Windows shows,
/// and what timestomping rewrites). FAT times are wall-clock times in an
/// unknown zone; exFAT times are UTC when they record their offset, and
/// wall-clock otherwise. [`Ts::semantic`] tells which.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Times {
    /// Created.
    pub created: Option<Ts>,
    /// Content last written.
    pub modified: Option<Ts>,
    /// Metadata last changed: the MFT entry, on NTFS only.
    pub changed: Option<Ts>,
    /// Last accessed (a date only on FAT). Windows updates it lazily, or
    /// not at all.
    pub accessed: Option<Ts>,
}

/// `ts` when it is a time, not a zero or an impossible value.
pub(crate) fn known(ts: Ts) -> Option<Ts> {
    ts.ticks().is_some().then_some(ts)
}
