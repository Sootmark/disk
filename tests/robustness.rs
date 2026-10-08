//! Hostile images: corrupt tables and file systems yield errors or fewer
//! files, never a panic that escapes the crate.

use std::io::{Cursor, Read};

use proptest::prelude::*;
use sootmark_disk::{identify, partitions, NtfsVolume};

const IMAGE: &[u8] = include_bytes!("fixtures/fin-wks-07.img");
/// Bytes read per file, as a real consumer would budget: declared sizes of
/// sparse files can be enormous.
const READ_BUDGET: u64 = 1 << 20;
/// The NTFS partition: sectors 256..2304.
const NTFS_RANGE: std::ops::Range<usize> = 256 * 512..2304 * 512;

/// Walk everything the image offers. Only a panic fails the test.
fn walk(image: Vec<u8>) {
    let length = image.len() as u64;
    let mut disk = Cursor::new(image);
    let Ok((_, parts)) = partitions(&mut disk, length) else {
        return;
    };
    for part in &parts {
        let _ = identify(&mut disk, part);
        let Ok(volume) = NtfsVolume::open(&mut disk, part.offset, part.length) else {
            continue;
        };
        let (Ok(files), Ok(indexes)) =
            (volume.files(&mut disk), volume.directory_indexes(&mut disk))
        else {
            continue;
        };
        for file in files.iter().chain(&indexes) {
            let _ = volume.read(&mut disk, file, &mut |r| {
                r.take(READ_BUDGET).read_to_end(&mut Vec::new()).map(|_| ())
            });
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn corrupted_partition_tables_never_panic(flips in proptest::collection::vec((0usize..34 * 512, any::<u8>()), 1..24)) {
        let mut image = IMAGE.to_vec();
        for (at, value) in flips {
            image[at] = value;
        }
        walk(image);
    }

    #[test]
    fn corrupted_ntfs_never_panics(flips in proptest::collection::vec((NTFS_RANGE, any::<u8>()), 1..48)) {
        let mut image = IMAGE.to_vec();
        for (at, value) in flips {
            image[at] = value;
        }
        walk(image);
    }
}

mod fat {
    use std::io::{Cursor, Read};
    use std::sync::OnceLock;

    use proptest::prelude::*;
    use sootmark_disk::FatVolume;

    use super::READ_BUDGET;

    fn volume(name: &str) -> &'static [u8] {
        static FAT12: OnceLock<Vec<u8>> = OnceLock::new();
        static EXFAT: OnceLock<Vec<u8>> = OnceLock::new();
        let cell = if name == "fat12" { &FAT12 } else { &EXFAT };
        cell.get_or_init(|| {
            let path = format!(
                "{}/tests/fixtures/fat/{name}.img.zlib",
                env!("CARGO_MANIFEST_DIR")
            );
            common::deflate::zlib_decompress(&std::fs::read(path).unwrap(), 64 << 20).unwrap()
        })
    }

    /// Open, list and read everything; only a panic (or a hang) fails.
    fn walk(image: Vec<u8>) {
        let length = image.len() as u64;
        let mut disk = Cursor::new(image);
        let Ok(volume) = FatVolume::open(&mut disk, 0, length) else {
            return;
        };
        for file in volume.files() {
            let _ = volume.read(&mut disk, &file, &mut |r| {
                r.take(READ_BUDGET).read_to_end(&mut Vec::new()).map(|_| ())
            });
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Boot sector, FATs and directories corrupted: never a panic.
        #[test]
        fn corrupted_fat_never_panics(flips in proptest::collection::vec((0usize..64 * 1024, any::<u8>()), 1..48)) {
            let mut image = volume("fat12").to_vec();
            for (at, value) in flips {
                image[at] = value;
            }
            walk(image);
        }

        #[test]
        fn corrupted_exfat_never_panics(flips in proptest::collection::vec((0usize..1 << 20, any::<u8>()), 1..48)) {
            let mut image = volume("exfat").to_vec();
            for (at, value) in flips {
                image[at] = value;
            }
            walk(image);
        }
    }
}

mod mft {
    use std::sync::OnceLock;

    use proptest::prelude::*;
    use sootmark_disk::Mft;

    fn loose() -> &'static [u8] {
        static MFT: OnceLock<Vec<u8>> = OnceLock::new();
        MFT.get_or_init(|| {
            let path = format!(
                "{}/tests/fixtures/mft/deleted.mft.zlib",
                env!("CARGO_MANIFEST_DIR")
            );
            common::deflate::zlib_decompress(&std::fs::read(path).unwrap(), 1 << 20).unwrap()
        })
    }

    /// Read everything, paths included; only a panic (or a hang) fails.
    fn walk(bytes: &[u8]) {
        for file in Mft::parse(bytes).files {
            let _ = file.display_path();
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..8192)) {
            walk(&bytes);
        }

        /// Records, attributes, names and parent references corrupted, and
        /// the end cut anywhere.
        #[test]
        fn corrupted_mft_never_panics(
            flips in proptest::collection::vec((0usize..88 * 1024, any::<u8>()), 1..64),
            cut in 0usize..88 * 1024,
        ) {
            let mut bytes = loose().to_vec();
            for (at, value) in flips {
                if let Some(byte) = bytes.get_mut(at) {
                    *byte = value;
                }
            }
            bytes.truncate(cut.max(1024));
            walk(&bytes);
        }
    }
}
