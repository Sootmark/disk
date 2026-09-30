//! NTFS-compressed files (LZNT1) on a volume written by ntfs-3g
//! (`tests/fixtures/ntfs-compressed.img.zlib`, 8 MiB, zlib-compressed for
//! the repository): text, incompressible, mixed and sparse files in a
//! compressed folder, and a plain copy, each read as ntfs-3g reads it
//! (`ntfs-compressed.sha256`).

use std::io::{Cursor, Read};
use std::path::Path;

use common::sha256::Sha256;
use sootmark_disk::NtfsVolume;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

#[test]
fn compressed_files_read_as_ntfs_3g_reads_them() {
    let image =
        common::deflate::zlib_decompress(&fixture("ntfs-compressed.img.zlib"), 8 << 20).unwrap();
    let expected = String::from_utf8(fixture("ntfs-compressed.sha256")).unwrap();
    let length = image.len() as u64;
    let mut disk = Cursor::new(image);
    let volume = NtfsVolume::open(&mut disk, 0, length).unwrap();
    let files = volume.files(&mut disk).unwrap();
    let mut checked = 0;
    for line in expected.lines() {
        let (digest, path) = line.split_once("  ").unwrap();
        let entry = files
            .iter()
            .find(|f| f.path.join("/") == path && f.stream.is_none())
            .unwrap_or_else(|| panic!("{path} not listed"));
        let mut hasher = Sha256::new();
        volume
            .read(&mut disk, entry, &mut |r| {
                std::io::copy(&mut r.take(64 << 20), &mut hasher).map(|_| ())
            })
            .unwrap();
        assert_eq!(common::hex::encode(&hasher.finalize()), digest, "{path}");
        checked += 1;
    }
    assert_eq!(checked, 6);
}
