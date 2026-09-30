//! FAT12, FAT16, FAT32 and exFAT volumes (`tests/fixtures/fat/`) against
//! The Sleuth Kit's reading of them: the same allocated files, each with
//! the same content.

use std::io::{Cursor, Read};
use std::path::Path;

use common::sha256::Sha256;
use sootmark_disk::{FatKind, FatVolume};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/fat")
            .join(name),
    )
    .unwrap()
}

fn listing(volume: &str) -> Vec<(String, String)> {
    let image = common::deflate::zlib_decompress(&fixture(&format!("{volume}.img.zlib")), 64 << 20)
        .unwrap();
    let length = image.len() as u64;
    let mut disk = Cursor::new(image);
    let fat = FatVolume::open(&mut disk, 0, length).unwrap();
    let mut out: Vec<(String, String)> = fat
        .files()
        .iter()
        .map(|entry| {
            let mut hasher = Sha256::new();
            fat.read(&mut disk, entry, &mut |r| {
                std::io::copy(&mut r.take(64 << 20), &mut hasher).map(|_| ())
            })
            .unwrap();
            (
                entry.path.join("/"),
                common::hex::encode(&hasher.finalize()),
            )
        })
        .collect();
    out.sort();
    out
}

fn tsk(volume: &str) -> Vec<(String, String)> {
    let text = String::from_utf8(fixture(&format!("{volume}.sha256"))).unwrap();
    let mut out: Vec<(String, String)> = text
        .lines()
        .filter_map(|l| l.split_once("  "))
        // TSK lists the volume label as a file; it isn't one.
        .filter(|(_, path)| !path.ends_with("(Volume Label Entry)"))
        .map(|(digest, path)| (path.to_owned(), digest.to_owned()))
        .collect();
    out.sort();
    out
}

#[test]
fn every_variant_reads_as_the_sleuth_kit_reads_it() {
    for (volume, kind) in [
        ("fat12", FatKind::Fat12),
        ("fat16", FatKind::Fat16),
        ("fat32", FatKind::Fat32),
        ("exfat", FatKind::ExFat),
    ] {
        let image =
            common::deflate::zlib_decompress(&fixture(&format!("{volume}.img.zlib")), 64 << 20)
                .unwrap();
        let length = image.len() as u64;
        assert_eq!(
            FatVolume::open(&mut Cursor::new(image), 0, length)
                .unwrap()
                .kind(),
            kind
        );
        let ours = listing(volume);
        assert_eq!(ours.len(), 28, "{volume}");
        assert!(
            ours.iter()
                .any(|(p, _)| p == "Folder With Long Name/résumé été.txt"),
            "{volume}"
        );
        assert_eq!(ours, tsk(volume), "{volume}");
    }
}

/// A boot sector claiming more clusters than the volume holds: the count
/// is cut to what fits, and the files read as before.
#[test]
fn an_inflated_cluster_count_is_cut_to_the_volume() {
    let mut image = common::deflate::zlib_decompress(&fixture("exfat.img.zlib"), 64 << 20).unwrap();
    image[92..96].copy_from_slice(&u32::MAX.to_le_bytes());
    let length = image.len() as u64;
    let mut disk = Cursor::new(image);
    let fat = FatVolume::open(&mut disk, 0, length).unwrap();
    assert_eq!(fat.files().len(), 28);
}

/// A small FAT32 (fewer clusters than the specification's FAT32 minimum,
/// as Linux writes them): the `E:` volume of `fin-wks-07.img`, generated
/// by `tests/fixtures/make-samples.py`, read as FAT32 from its boot sector.
#[test]
fn a_small_fat32_is_read_as_fat32() {
    let image =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fin-wks-07.img"))
            .unwrap();
    let length = image.len() as u64;
    let mut disk = Cursor::new(image);
    let (_, parts) = sootmark_disk::partitions(&mut disk, length).unwrap();
    let part = parts.iter().find(|p| p.slot == 2).unwrap();
    let fat = FatVolume::open(&mut disk, part.offset, part.length).unwrap();
    assert_eq!(fat.kind(), FatKind::Fat32);
    let paths: Vec<String> = fat.files().iter().map(|f| f.path.join("/")).collect();
    assert_eq!(
        paths,
        [
            "System Volume Information/IndexerVolumeGuid",
            "exfil/Q3_forecast_board_pack.zip",
            "exfil/payroll_2026-08.csv",
            "exfil/vendor_master.csv",
        ]
    );
    let payroll = &fat.files()[2];
    let mut hasher = Sha256::new();
    fat.read(&mut disk, payroll, &mut |r| {
        std::io::copy(r, &mut hasher).map(|_| ())
    })
    .unwrap();
    // The generator's PAYROLL content.
    assert_eq!(
        common::hex::encode(&hasher.finalize()),
        "ed84d3f9d569e907de906f59b1514fe55fd3475b10a22f081fad2579c1037727"
    );
}
