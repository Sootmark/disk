//! The synthetic FIN-WKS-07 disk (see `tests/fixtures/make-samples.py`),
//! checked against The Sleuth Kit: `mmls`, `fls -r -p -o 256` and `icat`.

use std::fs::File;
use std::io::{BufReader, Read, Seek};

use common::sha256::{hex, Sha256};
use disk::{
    identify, partitions, FileEntry, Filesystem, NtfsVolume, PartitionType, Scheme, SplitImage,
    SECTOR_SIZE,
};

const IMAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fin-wks-07.img");
const BASIC_DATA: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";

fn image() -> (BufReader<File>, u64) {
    let file = File::open(IMAGE).expect("fixture");
    let length = file.metadata().unwrap().len();
    (BufReader::new(file), length)
}

fn ntfs_volume<R: Read + Seek>(disk: &mut R, length: u64) -> NtfsVolume {
    let (_, parts) = partitions(disk, length).unwrap();
    NtfsVolume::open(disk, parts[1].offset, parts[1].length).unwrap()
}

fn sha256_of<R: Read + Seek>(volume: &NtfsVolume, disk: &mut R, entry: &FileEntry) -> String {
    let mut hasher = Sha256::new();
    volume
        .read(disk, entry, &mut |reader| {
            std::io::copy(reader, &mut hasher).map(|_| ())
        })
        .unwrap();
    hex(&hasher.finalize())
}

#[test]
fn partitions_match_mmls() {
    let (mut disk, length) = image();
    let (scheme, parts) = partitions(&mut disk, length).unwrap();
    assert_eq!(scheme, Scheme::Gpt);
    let layout: Vec<(u64, u64)> = parts
        .iter()
        .map(|p| (p.offset / SECTOR_SIZE, p.length / SECTOR_SIZE))
        .collect();
    assert_eq!(layout, [(128, 128), (256, 2048), (2432, 1024)]);
    assert_eq!(
        parts[0].name.as_deref(),
        Some("Microsoft reserved partition")
    );
    assert_eq!(parts[1].kind, PartitionType::Gpt(BASIC_DATA.into()));
}

#[test]
fn identifies_file_systems() {
    let (mut disk, length) = image();
    let (_, parts) = partitions(&mut disk, length).unwrap();
    let found: Vec<Filesystem> = parts
        .iter()
        .map(|p| identify(&mut disk, p).unwrap())
        .collect();
    assert_eq!(
        found,
        [Filesystem::Unknown, Filesystem::Ntfs, Filesystem::Fat]
    );
}

#[test]
fn lists_the_same_allocated_files_and_streams_as_fls() {
    let (mut disk, length) = image();
    let volume = ntfs_volume(&mut disk, length);
    let mut listed: Vec<String> = volume
        .files(&mut disk)
        .unwrap()
        .iter()
        .map(FileEntry::display_path)
        .collect();
    listed.sort();
    let mut expected = vec![
        r"ProgramData\Intel\m64.exe",
        r"Users\Public\rclone.exe",
        r"Users\svc_backup\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        r"Users\svc_backup\AppData\Roaming\rclone\rclone.conf",
        r"Users\svc_backup\Downloads\tools.zip",
        r"Users\svc_backup\Downloads\tools.zip:Zone.Identifier",
        "$AttrDef",
        "$BadClus",
        "$BadClus:$Bad",
        "$Bitmap",
        "$Boot",
        "$LogFile",
        "$MFT",
        "$MFTMirr",
        "$Secure",
        "$UpCase",
        "$Volume",
    ];
    expected.sort_unstable();
    assert_eq!(listed, expected);
}

#[test]
fn content_matches_icat() {
    let (mut disk, length) = image();
    let volume = ntfs_volume(&mut disk, length);
    let files = volume.files(&mut disk).unwrap();
    let by_path = |path: &str| {
        files
            .iter()
            .find(|f| f.display_path() == path)
            .unwrap_or_else(|| panic!("{path} listed"))
    };
    let expected = [
        (
            r"Users\svc_backup\AppData\Roaming\rclone\rclone.conf",
            "8c4dc8c2ac27226bb585cff90ecec13394bd51e792296d1333ef178df5a2f57f",
        ),
        (
            r"Users\svc_backup\Downloads\tools.zip:Zone.Identifier",
            "ca9dfb47c66ad01c49bf8f5841d734da9e5828a6c11a6a5bc0b726bf21e1973a",
        ),
        (
            r"Users\Public\rclone.exe",
            "8a0ce805e02df10fb7d025f73a9b9d8fd039cd262b7761b4d9f5edcfb5db4e57",
        ),
        (
            r"Users\svc_backup\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            "46a48fa30a543c6a4b7cff88868cbdac7624ebc1f0a7cb91788222b40e8245ca",
        ),
        (
            "$MFT",
            "7401eb91b96bfabbc89c1284ec1a572693625ae96d5e76b40ffb353d9fc906ac",
        ),
    ];
    for (path, sha256) in expected {
        assert_eq!(
            sha256_of(&volume, &mut disk, by_path(path)),
            sha256,
            "{path}"
        );
    }
    assert_eq!(by_path("$MFT").size, 65_536);
    assert_eq!(by_path(r"Users\Public\rclone.exe").size, 6_000);
}

#[test]
fn split_images_read_like_the_whole_image() {
    let dir = std::env::temp_dir().join(format!("disk-split-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let whole = std::fs::read(IMAGE).unwrap();
    let chunk = whole.len() / 3 + 1;
    for (i, part) in whole.chunks(chunk).enumerate() {
        std::fs::write(dir.join(format!("fin.{:03}", i + 1)), part).unwrap();
    }
    let mut split = SplitImage::open(&dir.join("fin.001")).unwrap();
    assert_eq!(split.len(), whole.len() as u64);
    let length = split.len();
    let volume = ntfs_volume(&mut split, length);
    assert_eq!(volume.files(&mut split).unwrap().len(), 17);
    std::fs::remove_dir_all(dir).unwrap();
}
