//! Directory indexes (`$INDEX_ALLOCATION:$I30`) on a volume written by
//! ntfs-3g (`tests/fixtures/indexes/`, recreated by `make-indexes.py`):
//! every directory whose index outgrew its record, read as The Sleuth Kit's
//! `icat` reads it (`indexes.oracle`).

use std::io::{Cursor, Read};
use std::path::Path;

use common::sha256::Sha256;
use sootmark_disk::{FileEntry, NtfsVolume, StreamKind};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/indexes")
            .join(name),
    )
    .unwrap()
}

fn volume() -> (NtfsVolume, Cursor<Vec<u8>>) {
    let image = common::deflate::zlib_decompress(&fixture("indexes.img.zlib"), 8 << 20).unwrap();
    let length = image.len() as u64;
    let mut disk = Cursor::new(image);
    let volume = NtfsVolume::open(&mut disk, 0, length).unwrap();
    (volume, disk)
}

/// `record  size  sha256  path`, as the oracle has it.
fn line_of(volume: &NtfsVolume, disk: &mut Cursor<Vec<u8>>, entry: &FileEntry) -> String {
    let mut hasher = Sha256::new();
    volume
        .read(disk, entry, &mut |r| {
            std::io::copy(&mut r.take(1 << 20), &mut hasher).map(|_| ())
        })
        .unwrap();
    let digest = common::hex::encode(&hasher.finalize());
    let path = entry.path.join("/");
    format!("{}\t{}\t{digest}\t{path}", entry.record, entry.size)
}

#[test]
fn directory_indexes_read_as_icat_reads_them() {
    let (volume, mut disk) = volume();
    let expected: Vec<String> = String::from_utf8(fixture("indexes.oracle"))
        .unwrap()
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            // The attribute identifier is only there for `icat`.
            [fields[0], fields[2], fields[3], fields[4]].join("\t")
        })
        .collect();
    let indexes = volume.directory_indexes(&mut disk).unwrap();
    let found: Vec<String> = indexes
        .iter()
        .map(|entry| line_of(&volume, &mut disk, entry))
        .collect();
    // Sorted by path, the root (empty path) first; `small` fits its record.
    assert_eq!(found, expected);
    assert!(indexes
        .iter()
        .all(|entry| entry.kind == StreamKind::DirectoryIndex
            && entry.stream.as_deref() == Some("$I30")));
}

#[test]
fn indexes_are_not_files() {
    let (volume, mut disk) = volume();
    let files = volume.files(&mut disk).unwrap();
    assert!(files.iter().all(|file| file.kind == StreamKind::Data));
    assert!(files
        .iter()
        .any(|file| file.path == ["docs", "report_001.txt"]));
}

#[test]
fn display_paths_name_the_attribute() {
    let (volume, mut disk) = volume();
    let indexes = volume.directory_indexes(&mut disk).unwrap();
    let paths: Vec<String> = indexes.iter().map(FileEntry::display_path).collect();
    assert_eq!(paths[0], ":$I30:$INDEX_ALLOCATION");
    assert!(paths.contains(&"Users\\alice\\Documents:$I30:$INDEX_ALLOCATION".to_owned()));
}
