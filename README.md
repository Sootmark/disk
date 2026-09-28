# disk

Disk images for forensic intake: raw and split raw images, GPT and MBR partition tables, file-system identification, and NTFS file listing with streaming reads, alternate data streams included. Nothing is extracted to disk. Written from scratch; the only dependency is [`Sootmark/common`](https://github.com/Sootmark/common).

```toml
[dependencies]
sootmark-disk = "0.2"
```

```rust
use sootmark_disk::{identify, partitions, Filesystem, NtfsVolume, SplitImage};

let mut image = SplitImage::open("case/fin-wks-07.001".as_ref())?;
let length = image.len();
let (_scheme, parts) = partitions(&mut image, length)?;
for part in &parts {
    if identify(&mut image, part)? == Filesystem::Ntfs {
        let volume = NtfsVolume::open(&mut image, part.offset, part.length)?;
        for file in volume.files(&mut image)? {
            println!("{} ({} bytes)", file.display_path(), file.size);
        }
    }
}
```

Any `Read + Seek` works as a disk, so container formats (VHDX, E01) plug in by providing one.

## Verified against The Sleuth Kit

`tests/fixtures/fin-wks-07.img` is a synthetic 1.7 MB GPT disk (NTFS `C:` and FAT32 `E:`, an alternate data stream, a timestomped file, a deleted file), generated deterministically by `tests/fixtures/make-samples.py` (no real data). Against `mmls`, `fls -r -p` and `icat`:

| Check | Result |
|---|---|
| Partitions (offsets, lengths, names, types) | identical to `mmls` |
| Allocated files and alternate data streams | identical set to `fls` (17 entries, `tools.zip:Zone.Identifier` included) |
| File contents (`$MFT`, `rclone.conf`, `Zone.Identifier`, …) | byte-identical to `icat` (SHA-256) |
| Split images (`.001`, `.002`, …) | read identically to the whole image |

## How NTFS is read

The MFT is walked record by record, the way forensic MFT parsers do: update-sequence fixups are verified (torn writes are detected, never silently accepted), paths are rebuilt from each record's `$FILE_NAME` parent reference, and attributes stored in extension records are merged into their base record. Files whose parent chain is broken are placed under `$OrphanFiles`, as The Sleuth Kit does. Sparse ranges and data past the initialized length read as zeros.

## Hostile images

Corrupted partition tables, MFT records and data runs yield errors or fewer files, never a crash (fuzzed with tens of thousands of corrupted images). Arithmetic on sizes and cluster numbers read from disk is checked.

Declared sizes are not proof of data: sparse streams (`$UsnJrnl:$J`) legitimately declare far more than they store, and a corrupt record can declare anything. Bound what you read; the fuzz tests do.

## Scope

NTFS allocated files and named streams. Not yet: compressed (LZNT1) and encrypted (EFS) streams (reported as unsupported), deleted files, carving, FAT/exFAT listing, Volume Shadow Copies (FAT and exFAT are identified).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
