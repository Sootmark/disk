//! File times on small NTFS, FAT12 and exFAT volumes written on Linux
//! (`tests/fixtures/times/`, recreated by `make-times.py`), against
//! independent readers: The Sleuth Kit's `istat` for NTFS (agreeing with
//! ntfs-3g), the Linux kernel for FAT12 and exFAT (The Sleuth Kit ignores
//! exFAT's UTC offsets).

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use common::time::{Precision, Semantic, Ts};
use sootmark_disk::{FatVolume, FileEntry, NtfsVolume, Times};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/times")
            .join(name),
    )
    .unwrap()
}

fn files(volume: &str) -> Vec<FileEntry> {
    let image =
        common::deflate::zlib_decompress(&fixture(&format!("{volume}.img.zlib")), 4 << 20).unwrap();
    let length = image.len() as u64;
    let mut disk = Cursor::new(image);
    if volume == "ntfs" {
        let ntfs = NtfsVolume::open(&mut disk, 0, length).unwrap();
        ntfs.files(&mut disk).unwrap()
    } else {
        FatVolume::open(&mut disk, 0, length).unwrap().files()
    }
}

fn find<'a>(files: &'a [FileEntry], path: &str) -> &'a Times {
    &files
        .iter()
        .find(|f| slash_path(f) == path)
        .unwrap_or_else(|| panic!("{path} listed"))
        .times
}

fn slash_path(entry: &FileEntry) -> String {
    entry.display_path().replace('\\', "/")
}

/// `path -> [created, modified, changed, accessed]`, as the oracle writes
/// them: UTC, or the wall clock for times without a zone.
fn oracle(volume: &str) -> BTreeMap<String, Vec<String>> {
    String::from_utf8(fixture(&format!("{volume}.times")))
        .unwrap()
        .lines()
        .map(|line| {
            let mut fields = line.split('\t').map(str::to_owned);
            (fields.next().unwrap(), fields.collect())
        })
        .collect()
}

fn as_oracle_writes(times: &Times) -> Vec<String> {
    [times.created, times.modified, times.changed, times.accessed]
        .iter()
        .map(|t| match t.and_then(|t| t.to_iso8601()) {
            Some(iso) => iso.trim_end_matches('Z').to_owned(),
            None => "-".to_owned(),
        })
        .collect()
}

fn iso(time: Option<Ts>) -> String {
    time.and_then(|t| t.to_iso8601()).unwrap()
}

#[test]
fn every_listed_file_has_the_times_independent_readers_see() {
    for volume in ["ntfs", "fat12", "exfat"] {
        let expected = oracle(volume);
        let files = files(volume);
        for entry in &files {
            let path = slash_path(entry);
            let theirs = expected
                .get(&path)
                .unwrap_or_else(|| panic!("{volume}: {path} not in the oracle"));
            assert_eq!(&as_oracle_writes(&entry.times), theirs, "{volume}: {path}");
        }
        // NTFS's oracle also lists index streams ($ObjId:$O), which aren't
        // data streams.
        if volume != "ntfs" {
            assert_eq!(files.len(), expected.len(), "{volume}");
        }
    }
}

#[test]
fn ntfs_times_are_utc_to_the_tick_and_streams_share_them() {
    let files = files("ntfs");
    let report = find(&files, "report.txt");
    assert_eq!(find(&files, "report.txt:Zone.Identifier"), report);
    assert_eq!(iso(report.created), "2001-09-09T01:46:40.1234567Z");
    assert_eq!(iso(report.modified), "2004-11-09T11:33:20.0000002Z");
    assert_eq!(iso(report.accessed), "2008-01-10T21:20:00.9999999Z");
    assert!(report.changed.is_some());
    assert_eq!(
        iso(find(&files, "logs/app.log").modified),
        "2023-06-15T08:30:00.5000000Z"
    );
    // mkfs.ntfs leaves $MFT's times zero: not set.
    assert_eq!(*find(&files, "$MFT"), Times::default());
}

#[test]
fn fat_times_are_wall_clock() {
    let files = files("fat12");
    let report = find(&files, "Quarterly Report.docx");
    let modified = report.modified.unwrap();
    assert_eq!(modified.semantic(), Semantic::LocalUnknownZone);
    assert_eq!(modified.precision(), Precision::TwoSeconds);
    // Written at 05:06:07.89: FAT keeps even seconds.
    assert_eq!(iso(report.modified), "2021-03-04T05:06:06.0000000");
    let accessed = report.accessed.unwrap();
    assert_eq!(accessed.precision(), Precision::Day);
    assert_eq!(iso(report.accessed), "2022-01-02T00:00:00.0000000");
    assert_eq!(report.created.unwrap().precision(), Precision::Millisecond);
    assert_eq!(report.changed, None);
    assert_eq!(
        iso(find(&files, "Archive/old.txt").modified),
        "1980-01-01T00:00:00.0000000"
    );
}

#[test]
fn exfat_times_are_utc_when_they_record_their_offset() {
    let files = files("exfat");
    // The same wall-clock write, 05:06:07.89, under different offsets.
    for (path, modified) in [
        ("utc.txt", "2021-03-04T05:06:07.8900000Z"),
        ("plus-two.txt", "2021-03-04T03:06:07.8900000Z"),
        ("minus-five.txt", "2021-03-04T10:06:07.8900000Z"),
        ("no-zone.txt", "2021-03-04T05:06:07.8900000"),
    ] {
        assert_eq!(iso(find(&files, path).modified), modified, "{path}");
    }
    let no_zone = find(&files, "no-zone.txt");
    for time in [no_zone.created, no_zone.modified, no_zone.accessed] {
        assert_eq!(time.unwrap().semantic(), Semantic::LocalUnknownZone);
    }
    assert_eq!(find(&files, "utc.txt").changed, None);
}
