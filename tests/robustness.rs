//! Hostile images: corrupt tables and file systems yield errors or fewer
//! files, never a panic that escapes the crate.

use std::io::{Cursor, Read};

use disk::{identify, partitions, NtfsVolume};
use proptest::prelude::*;

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
        let Ok(files) = volume.files(&mut disk) else {
            continue;
        };
        for file in &files {
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
