# disk

Disk images for forensic intake: raw and split raw images, GPT and MBR partition tables, file-system identification, and NTFS, FAT and exFAT file listing (with times) and streaming reads, alternate data streams included. Nothing is extracted to disk. Written from scratch; the only dependency is [`Sootmark/common`](https://github.com/Sootmark/common).

```toml
[dependencies]
sootmark-disk = "0.3"
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
            let modified = file.times.modified.map_or("-".into(), |t| t.to_string());
            println!("{} ({} bytes, modified {modified})", file.display_path(), file.size);
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

FAT and exFAT: `tests/fixtures/fat/` holds a FAT12, a FAT16, a FAT32 and an exFAT volume written on Linux (long names with accents, nested folders, files fragmented around deleted ones, an empty file); every allocated file and its content match The Sleuth Kit (`fls`, `icat`). On NIST's CFReDS Data Leakage USB images (not redistributed), the exFAT drive's files match TSK's allocated tree; the FAT32 drive holds none (its files were deleted).

Compressed files (LZNT1): `tests/fixtures/ntfs-compressed.img.zlib` is a volume written by ntfs-3g (a compressed folder holding text, incompressible, mixed and sparse files, and a plain copy); every file reads as ntfs-3g reads it. On a real Windows Server 2022 image (CFReDS "Compromised Windows Server 2022", not redistributed), all 268 compressed files read identically to ntfs-3g.

Times: `tests/fixtures/times/` holds small NTFS, FAT12 and exFAT volumes written on Linux with known times (sub-second NTFS times, an odd-second FAT write, exFAT entries carrying +02:00, -05:00 and no valid offset), recreated by `make-times.py`. Every listed file's times match `istat` on NTFS (itself checked against ntfs-3g) and the Linux kernel's reading on FAT12 and exFAT (The Sleuth Kit 4.12 ignores exFAT's offsets). On `fin-wks-07.img`, the timestomped `m64.exe` reads with its rolled-back `$STANDARD_INFORMATION` times, as `istat` shows them.

## Times

Every listed file carries `Times`: created, modified, changed and accessed, each a [`Ts`](https://docs.rs/sootmark-common/latest/sootmark_common/time/struct.Ts.html) that says what it is, or `None` when the file system doesn't keep that time or the stored value is zero or impossible.

| File system | Source | Zone | Resolution |
|---|---|---|---|
| NTFS | `$STANDARD_INFORMATION` (what Windows shows, and what timestomping rewrites); an alternate data stream has its file's | UTC | 100 ns; `changed` is the MFT entry's |
| FAT12/16/32 | directory entry | wall-clock, zone unknown: never passed off as UTC | 2 s; creation 10 ms; last access a date |
| exFAT | File entry | UTC when its offset is marked valid, wall-clock otherwise | 2 s; creation and modification 10 ms |

`changed` exists on NTFS only. `$FILE_NAME` times aren't exposed.

## How NTFS is read

The MFT is walked record by record, the way forensic MFT parsers do: update-sequence fixups are verified (torn writes are detected, never silently accepted), paths are rebuilt from each record's `$FILE_NAME` parent reference, and attributes stored in extension records are merged into their base record. Files whose parent chain is broken are placed under `$OrphanFiles`, as The Sleuth Kit does. Sparse ranges and data past the initialized length read as zeros. Compressed streams are read a compression unit (16 clusters) at a time: all clusters allocated means stored as is, none means zeros, and allocated clusters ending early hold LZNT1 data.

## Hostile images

Corrupted partition tables, MFT records and data runs yield errors or fewer files, never a crash (fuzzed with tens of thousands of corrupted images). Arithmetic on sizes and cluster numbers read from disk is checked.

Declared sizes are not proof of data: sparse streams (`$UsnJrnl:$J`) legitimately declare far more than they store, and a corrupt record can declare anything. Bound what you read; the fuzz tests do.

## Scope

NTFS allocated files and named streams, compressed (LZNT1) streams decompressed a compression unit at a time. FAT12, FAT16, FAT32 and exFAT volumes: allocated files (long names included) listed and read through their cluster chains. File times on all of them. Not yet: encrypted (EFS) streams (reported as unsupported), deleted files, carving, Volume Shadow Copies.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
