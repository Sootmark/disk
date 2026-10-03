//! Loose `$MFT` files (`tests/fixtures/mft/`, recreated by `make-mft.py`),
//! against independent readers: The Sleuth Kit for the `$MFT` of
//! `fin-wks-07.img`, of the times volume, and of a volume with deleted
//! files and attribute lists; libfsntfs for plaso's sample.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use common::time::Ts;
use sootmark_disk::{partitions, Mft, MftFile, Namespace, NtfsVolume, Times};

const RECORD_SIZE: usize = 1024;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn inflate(name: &str) -> Vec<u8> {
    common::deflate::zlib_decompress(&fixture(name), 64 << 20).unwrap()
}

fn loose(name: &str) -> Vec<u8> {
    inflate(&format!("mft/{name}.mft.zlib"))
}

fn parse(name: &str) -> Mft {
    Mft::parse(&loose(name))
}

fn find<'a>(mft: &'a Mft, path: &str) -> &'a MftFile {
    mft.files
        .iter()
        .find(|f| f.display_path() == path)
        .unwrap_or_else(|| panic!("{path} listed"))
}

/// What the oracle says of one record: its F line, and its N, S and P
/// lines (see `make-mft.py`).
#[derive(Default)]
struct Facts {
    file: Vec<String>,
    names: Vec<Vec<String>>,
    streams: Vec<Vec<String>>,
    paths: Vec<String>,
}

fn oracle(name: &str) -> BTreeMap<u64, Facts> {
    let text = if name == "plaso" {
        inflate("mft/plaso.oracle.zlib")
    } else {
        fixture(&format!("mft/{name}.oracle"))
    };
    let mut records: BTreeMap<u64, Facts> = BTreeMap::new();
    for line in String::from_utf8(text).unwrap().lines() {
        let fields: Vec<String> = line.split('\t').map(str::to_owned).collect();
        let facts = records.entry(fields[1].parse().unwrap()).or_default();
        match fields[0].as_str() {
            "F" => facts.file = fields,
            "N" => facts.names.push(fields),
            "S" => facts.streams.push(fields),
            _ => facts.paths.push(fields[2].clone()),
        }
    }
    records
}

fn iso(time: Option<Ts>) -> String {
    time.and_then(|t| t.to_iso8601())
        .map_or("-".to_owned(), |iso| iso.trim_end_matches('Z').to_owned())
}

fn times(times: &Times) -> [String; 4] {
    [times.created, times.modified, times.changed, times.accessed].map(iso)
}

/// Our reading of `file`, in the oracle's line format.
fn facts(file: &MftFile) -> Facts {
    let record = file.record.to_string();
    let state = if file.in_use { "allocated" } else { "deleted" };
    let kind = if file.is_directory {
        "directory"
    } else {
        "file"
    };
    let mut head = fields(&["F", &record, state, kind, &file.sequence.to_string()]);
    head.extend(times(&file.times));
    let names = file.names.iter().map(|n| {
        let mut line = fields(&["N", &record]);
        line.extend(
            [
                n.parent,
                u64::from(n.parent_sequence),
                n.allocated_size,
                n.size,
            ]
            .map(|v| v.to_string()),
        );
        line.extend(times(&n.times));
        line.push(n.name.clone());
        line
    });
    let streams = file.streams.iter().map(|s| {
        let residency = if s.resident.is_some() {
            "resident"
        } else {
            "nonresident"
        };
        let name = s.name.as_deref().unwrap_or("-");
        fields(&["S", &record, name, residency, &s.size.to_string()])
    });
    Facts {
        file: head,
        names: names.collect(),
        streams: streams.collect(),
        paths: vec![file.path.join("/")],
    }
}

fn fields(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

/// `ours` with the fields the oracle doesn't know (`?`) masked.
fn masked(ours: &[String], theirs: &[String]) -> Vec<String> {
    ours.iter()
        .zip(theirs)
        .map(|(o, t)| if t == "?" { t.clone() } else { o.clone() })
        .collect()
}

/// Both sets of lines, sorted, the oracle's unknowns masked in ours.
fn same_lines(ours: &[Vec<String>], theirs: &[Vec<String>]) -> bool {
    let mut theirs = theirs.to_vec();
    theirs.sort();
    let mut ours: Vec<Vec<String>> = match theirs.first() {
        Some(template) => ours.iter().map(|o| masked(o, template)).collect(),
        None => ours.to_vec(),
    };
    ours.sort();
    ours == theirs
}

/// Every difference between our reading and the oracle's. Paths are
/// compared for named records only: The Sleuth Kit names nameless ones
/// `$OrphanFiles/OrphanFile-<record>`.
fn differences(name: &str) -> Vec<String> {
    let mft = parse(name);
    let mut expected = oracle(name);
    let mut differences = Vec::new();
    for file in &mft.files {
        let Some(theirs) = expected.remove(&file.record) else {
            differences.push(format!("{name}: record {} not in the oracle", file.record));
            continue;
        };
        let ours = facts(file);
        let path_known = theirs.paths.is_empty() || file.names.is_empty();
        let checks = [
            ("record", masked(&ours.file, &theirs.file) == theirs.file),
            ("$FILE_NAME", same_lines(&ours.names, &theirs.names)),
            ("$DATA", same_lines(&ours.streams, &theirs.streams)),
            ("path", path_known || theirs.paths.contains(&ours.paths[0])),
        ];
        for (what, _) in checks.iter().filter(|(_, same)| !same) {
            differences.push(format!("{name}: record {}: {what} differs", file.record));
        }
    }
    for record in expected.keys() {
        differences.push(format!("{name}: record {record} not read"));
    }
    differences.extend(mft.problems.iter().map(|p| format!("{name}: {p}")));
    differences
}

#[test]
fn every_record_reads_as_the_sleuth_kit_reads_it() {
    for name in ["fin-wks-07", "times", "deleted"] {
        let differences = differences(name);
        assert!(differences.is_empty(), "{differences:#?}");
    }
}

#[test]
fn every_record_of_plasos_sample_reads_as_libfsntfs_reads_it() {
    let differences = differences("plaso");
    assert!(differences.is_empty(), "{differences:#?}");
}

#[test]
fn deleted_files_keep_their_last_path() {
    let mft = parse("deleted");
    for path in [
        r"Temp\old.log",
        r"Temp\stage",
        r"Temp\stage\creds.txt",
        r"Temp\stage\notes.txt",
    ] {
        let file = find(&mft, path);
        assert!(!file.in_use && !file.is_orphan(), "{path}");
    }
    // Its folder's record now holds `Reused`: the chain is broken.
    let lost = find(&mft, r"$OrphanFiles\lost.txt");
    assert!(!lost.in_use && lost.is_orphan());
    let reused = find(&mft, "Reused");
    assert_eq!(lost.names[0].parent, reused.record);
    assert_eq!(reused.sequence, lost.names[0].parent_sequence + 1);
    assert!(reused.in_use);
    // fin-wks-07's deleted credential dump keeps its path too.
    assert!(!find(&parse("fin-wks-07"), r"ProgramData\Intel\creds.txt").in_use);
}

#[test]
fn extension_records_join_their_base_record() {
    let mft = parse("deleted");
    let links = mft
        .files
        .iter()
        .find(|f| f.names.iter().any(|n| n.name == "target.txt"))
        .unwrap();
    assert_eq!(links.names.len(), 25);
    assert!(links
        .display_path()
        .starts_with(r"Users\alice\links\hard-link-"));
    // `$DATA` split across records: the size is on the first piece.
    let fragmented = find(&mft, r"Users\alice\fragmented.bin");
    assert_eq!(fragmented.streams[0].size, 2_043_904);
    // Its deleted twin: ntfs-3g removed the name (moved to an extension
    // record) before freeing the records, but the data's pieces remain.
    let deleted = mft
        .files
        .iter()
        .find(|f| !f.in_use && f.streams.first().is_some_and(|s| s.size == 2_043_904))
        .unwrap();
    assert!(deleted.names.is_empty() && deleted.path.is_empty());
}

#[test]
fn small_streams_carry_their_content() {
    let mft = parse("deleted");
    let report = find(&mft, r"Users\alice\report.txt");
    let zone = report
        .streams
        .iter()
        .find(|s| s.name.as_deref() == Some("Zone.Identifier"))
        .unwrap();
    assert_eq!(
        zone.resident.as_deref(),
        Some(&b"[ZoneTransfer]\r\nZoneId=3\r\n"[..])
    );
    assert_eq!(
        report.streams[0].resident.as_deref(),
        Some(&b"Quarterly figures (placeholder).\n"[..])
    );
    let big = find(&mft, r"Users\alice\big.bin");
    assert_eq!(
        (big.streams[0].size, big.streams[0].resident.is_none()),
        (20_000, true)
    );
}

/// m64.exe is timestomped: its `$STANDARD_INFORMATION` says 2019, its
/// `$FILE_NAME` keeps the day it was dropped.
#[test]
fn file_name_times_expose_timestomping() {
    let mft = parse("fin-wks-07");
    let m64 = find(&mft, r"ProgramData\Intel\m64.exe");
    assert_eq!(iso(m64.times.created), "2019-03-18T04:12:00.0000000");
    assert_eq!(
        iso(m64.names[0].times.created),
        "2026-09-14T10:07:31.5261049"
    );
}

#[test]
fn names_prefer_windows_long_names() {
    let mft = parse("plaso");
    let with_alias = mft
        .files
        .iter()
        .find(|f| f.names.iter().any(|n| n.namespace == Namespace::Dos))
        .unwrap();
    let long = with_alias
        .names
        .iter()
        .find(|n| n.namespace == Namespace::Win32)
        .unwrap();
    assert_eq!(with_alias.path.last(), Some(&long.name));
}

#[test]
fn a_volumes_mft_reads_like_its_loose_copy() {
    let image = fixture("fin-wks-07.img");
    let mut disk = Cursor::new(image);
    let length = disk.get_ref().len() as u64;
    let (_, parts) = partitions(&mut disk, length).unwrap();
    let volume = NtfsVolume::open(&mut disk, parts[1].offset, parts[1].length).unwrap();
    assert_eq!(volume.mft(&mut disk).unwrap(), parse("fin-wks-07"));

    let image = inflate("times/ntfs.img.zlib");
    let length = image.len() as u64;
    let mut disk = Cursor::new(image);
    let volume = NtfsVolume::open(&mut disk, 0, length).unwrap();
    assert_eq!(volume.mft(&mut disk).unwrap(), parse("times"));
}

#[test]
fn reading_a_stream_matches_parsing_memory() {
    let bytes = loose("deleted");
    assert_eq!(Mft::read(Cursor::new(&bytes)).unwrap(), Mft::parse(&bytes));
}

/// The same records, 4096 bytes each (as on 4K-sector disks).
#[test]
fn record_size_comes_from_the_records() {
    let narrow = loose("deleted");
    let mut wide = Vec::new();
    for record in narrow.chunks(RECORD_SIZE) {
        wide.extend(widen(record));
    }
    assert_eq!(Mft::parse(&wide), Mft::parse(&narrow));
}

/// A 1024-byte record as a 4096-byte one: allocated size grown, and the
/// fixup array, grown to eight sectors, moved to the new free space.
fn widen(record: &[u8]) -> Vec<u8> {
    let mut wide = record.to_vec();
    wide.resize(4 * RECORD_SIZE, 0);
    if &record[..4] != b"FILE" {
        return wide;
    }
    let old = usize::from(u16::from_le_bytes([record[4], record[5]]));
    let new = RECORD_SIZE;
    wide[4..6].copy_from_slice(&(new as u16).to_le_bytes());
    wide[6..8].copy_from_slice(&9u16.to_le_bytes());
    wide[0x1c..0x20].copy_from_slice(&4096u32.to_le_bytes());
    wide.copy_within(old..old + 6, new);
    let marker = [record[old], record[old + 1]];
    for sector in 2..8 {
        let end = (sector + 1) * 512;
        wide.copy_within(end - 2..end, new + 2 * (sector + 1));
        wide[end - 2..end].copy_from_slice(&marker);
    }
    wide
}

#[test]
fn a_torn_record_is_a_problem_not_a_failure() {
    let mut bytes = loose("deleted");
    let report = find(&Mft::parse(&bytes), r"Users\alice\report.txt").record as usize;
    // The last two bytes of the record's first sector, where its update
    // sequence number should be.
    bytes[report * RECORD_SIZE + 510] ^= 0xff;
    let mft = Mft::parse(&bytes);
    assert_eq!(mft.problems.len(), 1);
    assert_eq!(mft.problems[0].record, Some(report as u64));
    assert!(mft.files.iter().all(|f| f.record != report as u64));
    assert!(find(&mft, r"Users\alice\big.bin").in_use);
}

#[test]
fn records_windows_marked_bad_and_a_cut_end_are_problems() {
    let mut bytes = loose("times");
    bytes[64 * RECORD_SIZE..64 * RECORD_SIZE + 4].copy_from_slice(b"BAAD");
    bytes.truncate(bytes.len() - 100);
    let mft = Mft::parse(&bytes);
    let last = (bytes.len() / RECORD_SIZE) as u64;
    let problems: Vec<Option<u64>> = mft.problems.iter().map(|p| p.record).collect();
    assert_eq!(problems, [Some(64), Some(last)]);
    assert!(mft.problems[0].to_string().contains("BAAD"));
}

#[test]
fn something_else_is_not_an_mft() {
    let mft = Mft::parse(&fixture("fin-wks-07.img")[..4096]);
    assert!(mft.files.is_empty());
    assert_eq!(mft.problems[0].record, None);
    assert_eq!(Mft::parse(&[]).files, []);
}

/// Users and alice made each other's parent: what is below them is
/// orphaned, with the part of the chain read before the loop.
#[test]
fn cycles_in_parent_references_end_in_orphans() {
    let mut bytes = loose("deleted");
    let mft = Mft::parse(&bytes);
    let alice = find(&mft, r"Users\alice").record;
    let users = find(&mft, "Users").record;
    let users_name = file_name_value(&bytes, users);
    bytes[users_name..users_name + 8].copy_from_slice(&(alice | 1 << 48).to_le_bytes());
    let mft = Mft::parse(&bytes);
    let report = mft
        .files
        .iter()
        .find(|f| f.path.last().is_some_and(|n| n == "report.txt"));
    assert_eq!(
        report.unwrap().display_path(),
        r"$OrphanFiles\Users\alice\report.txt"
    );
}

/// Where record `number`'s first `$FILE_NAME` value starts.
fn file_name_value(mft: &[u8], number: u64) -> usize {
    let start = number as usize * RECORD_SIZE;
    let record = &mft[start..start + RECORD_SIZE];
    let mut offset = usize::from(u16::from_le_bytes([record[0x14], record[0x15]]));
    loop {
        let kind = u32::from_le_bytes(record[offset..offset + 4].try_into().unwrap());
        let length = u32::from_le_bytes(record[offset + 4..offset + 8].try_into().unwrap());
        if kind == 0x30 {
            let value = u16::from_le_bytes([record[offset + 20], record[offset + 21]]);
            return start + offset + usize::from(value);
        }
        offset += length as usize;
    }
}
