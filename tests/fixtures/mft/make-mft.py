#!/usr/bin/env python3
"""Recreate the loose `$MFT` fixtures and what independent readers make of
them.

    sudo python3 make-mft.py PLASO_MFT [out_dir]      (default: this directory)

Linux only (loop mounts): ntfs-3g, sleuthkit, python3-libfsntfs. PLASO_MFT
is `test_data/MFT` from plaso (Apache-2.0, commit e105c77d). No real data:
every other file is a placeholder written here or by `make-samples.py`.

Each `<name>.mft.zlib` is a `$MFT` as a triage collection copies it
(zlib-compressed for the repository), and `<name>.oracle` (zlib-compressed
too for plaso's) what an independent reader sees in it, one tab-separated
fact per line:

    F  record  allocated|deleted  directory|file  sequence  si_created  si_modified  si_changed  si_accessed
    N  record  parent  parent_sequence  allocated_size  size  created  modified  changed  accessed  name
    S  record  stream|-  resident|nonresident|?  size
    P  record  path

F is a base record (with its `$STANDARD_INFORMATION` times), N one of its
`$FILE_NAME` attributes, S one of its `$DATA` streams (`-`: the default
one), P a path the reader gives it. Times are UTC `YYYY-MM-DDTHH:MM:SS.fffffff`
(`-`: zero, not set); `?` is what the reader doesn't tell.

- `fin-wks-07`, `times`: the `$MFT` of `../fin-wks-07.img` and of
  `../times/ntfs.img.zlib`.
- `deleted`: a volume written here with ntfs-3g: deleted files (in a live
  folder, in a deleted folder, and under a folder whose record was reused),
  an alternate data stream, and two files whose attributes overflow into
  extension records (`$ATTRIBUTE_LIST`): one with 24 hard links, one
  sparse and fragmented into 500 runs (its non-resident attribute list,
  which a loose `$MFT` can't read, splits `$DATA` across records), plus a
  deleted one like it.

For those three the oracle is The Sleuth Kit (`istat` for records, `fls -r
-p` for paths, `icat` extracts the `$MFT`).

- `plaso`: the first 6000 records of plaso's `test_data/MFT` (a Windows XP
  system volume; truncated to keep the fixtures small, so files whose
  parent lies beyond are orphans). The oracle is libfsntfs (`pyfsntfs`),
  which reads loose `$MFT` files; it tells neither residency nor
  `$FILE_NAME` sizes, and gives one path per record (its "path hint").
"""

import os
import re
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLASO_RECORDS = 6000
RECORD_NUMBER_MASK = (1 << 48) - 1
FILETIME_UNIX_OFFSET = 116_444_736_000_000_000
# How `istat` prints a zero FILETIME (see ../times/make-times.py).
TSK_ZERO_FILETIME = "2076-11-29T08:54:34.0000000"
TIME_LABELS = ["Created", "File Modified", "MFT Modified", "Accessed"]


def run(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def run_bytes(*args: str) -> bytes:
    return subprocess.run(args, check=True, capture_output=True).stdout


class Mount:
    def __init__(self, image: Path):
        self.image = image
        self.point = Path(tempfile.mkdtemp())

    def __enter__(self) -> Path:
        run("mount", "-t", "ntfs-3g", "-o", "loop,rw", str(self.image), str(self.point))
        return self.point

    def __exit__(self, *_) -> None:
        run("umount", str(self.point))
        self.point.rmdir()


def write(root: Path, relative: str, content: bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


# ================================================================ volume ===

def fragmented(path: Path, clusters: int, cluster_size: int) -> None:
    """Write every other cluster, leaving sparse holes between: the run
    list alternates data and holes, and overflows its record."""
    f = os.open(path, os.O_WRONLY | os.O_CREAT, 0o644)
    for i in range(clusters):
        os.pwrite(f, b"\xa5" * cluster_size, 2 * i * cluster_size)
    os.close(f)


def make_deleted_volume(work: Path) -> Path:
    image = work / "deleted.img"
    image.write_bytes(b"")
    os.truncate(image, 6 << 20)
    run("mkfs.ntfs", "-q", "-F", "-f", "-s", "512", "-c", "4096", "-L", "DELETED", str(image))
    with Mount(image) as root:
        write(root, "Gone/lost.txt", b"in a folder whose record gets reused\n")
        report = write(root, "Users/alice/report.txt", b"Quarterly figures (placeholder).\n")
        os.setxattr(report, "user.Zone.Identifier", b"[ZoneTransfer]\r\nZoneId=3\r\n")
        write(root, "Users/alice/big.bin", b"big\n" * 5000)  # non-resident
        target = write(root, "Users/alice/links/target.txt", b"one file, many names\n")
        for i in range(24):
            os.link(target, target.parent / f"hard-link-with-a-rather-long-name-{i:02}.txt")
        (root / "Temp").mkdir()
        for path in ["Users/alice/fragmented.bin", "Temp/fragmented.bin"]:
            fragmented(root / path, 250, 4096)
        write(root, "Temp/old.log", b"deleted from a live folder\n")
        write(root, "Temp/stage/creds.txt", b"deleted with its folder\n")
        write(root, "Temp/stage/notes.txt", b"deleted with its folder too\n")
    with Mount(image) as root:
        (root / "Gone/lost.txt").unlink()
        (root / "Gone").rmdir()
        (root / "Temp/old.log").unlink()
        for name in ["creds.txt", "notes.txt"]:
            (root / "Temp/stage" / name).unlink()
        (root / "Temp/stage").rmdir()
        (root / "Temp/fragmented.bin").unlink()
    with Mount(image) as root:
        # ntfs-3g allocates the lowest free record: Gone's.
        (root / "Reused").mkdir()
    return image


# ================================================================ oracles ===

def iso_from_istat(text: str) -> str:
    """`2001-09-09 01:46:40.123456700 (UTC)` -> `2001-09-09T01:46:40.1234567`."""
    match = re.fullmatch(r"(\S+) (\d\d:\d\d:\d\d)(?:\.(\d{7})\d*)? \(UTC\)", text.strip())
    if not match:
        raise SystemExit(f"unexpected istat time: {text!r}")
    iso = f"{match[1]}T{match[2]}.{match[3] or '0000000'}"
    return "-" if iso == TSK_ZERO_FILETIME else iso


def iso_from_filetime(value: int) -> str:
    if value == 0:
        return "-"
    ticks = value - FILETIME_UNIX_OFFSET
    seconds, fraction = divmod(ticks, 10_000_000)
    stamp = run("date", "-u", "-d", f"@{seconds}", "+%Y-%m-%dT%H:%M:%S").strip()
    return f"{stamp}.{fraction:07d}"


def base_records(mft: bytes) -> list[int]:
    """Record numbers of base records (in use or not): extension records
    belong to their base."""
    size = struct.unpack_from("<I", mft, 0x1C)[0]
    numbers = []
    for number in range(len(mft) // size):
        record = mft[number * size:(number + 1) * size]
        if record[:4] == b"FILE" and struct.unpack_from("<Q", record, 0x20)[0] == 0:
            numbers.append(number)
    return numbers


def istat_lines(image: Path, offset: int, number: int) -> list[str]:
    out = run("istat", "-z", "UTC", "-o", str(offset), str(image), str(number))
    lines, section, times, si = [], None, [], None
    name = parent = sizes = None
    for line in out.splitlines():
        if line.startswith("Entry:"):
            sequence = re.search(r"Sequence: (\d+)", line)[1]
        elif re.fullmatch(r"(Not )?Allocated (File|Directory)", line):
            state = "deleted" if line.startswith("Not") else "allocated"
            kind = "directory" if line.endswith("Directory") else "file"
        elif line.endswith("Attribute Values:"):
            section, times = line.split()[0], []
        elif line.startswith("Name: ") and section == "$FILE_NAME":
            name = line[len("Name: "):]
        elif line.startswith("Parent MFT Entry:"):
            parent = re.findall(r"\d+", line)
        elif line.startswith("Allocated Size:"):
            sizes = re.findall(r"\d+", line)
        elif line.partition(":\t")[0] in TIME_LABELS and section in ("$STANDARD_INFORMATION", "$FILE_NAME"):
            times.append(iso_from_istat(line.partition(":\t")[2]))
            if len(times) == 4 and section == "$STANDARD_INFORMATION":
                si = times
            elif len(times) == 4:
                lines.append("\t".join(["N", str(number), *parent, *sizes, *times, name]))
        elif line.startswith("Type: $DATA"):
            match = re.match(r"Type: \$DATA \(\d+-\d+\)\s+Name: (.*?)\s+(Resident|Non-Resident)(?:, \w+)*\s+size: (\d+)", line)
            stream = "-" if match[1] == "N/A" else match[1]
            residency = "resident" if match[2] == "Resident" else "nonresident"
            lines.append("\t".join(["S", str(number), stream, residency, match[3]]))
    head = ["F", str(number), state, kind, sequence, *(si or ["-"] * 4)]
    return ["\t".join(head), *lines]


def fls_paths(image: Path, offset: int) -> list[str]:
    """One P line per name `fls` finds, deleted ones included (not names
    whose record was reallocated, nor stream entries)."""
    lines = set()
    for line in run("fls", "-r", "-p", "-o", str(offset), str(image)).splitlines():
        kinds, path = line.split("\t", 1)
        if "(realloc)" in kinds or kinds.startswith(("v/v", "V/V")):
            continue
        address = kinds.split()[-1].rstrip(":")
        number = address.split("-")[0]
        if ":" in path:
            continue  # an alternate data stream of a listed file
        lines.add(f"P\t{number}\t{path}")
    return sorted(lines, key=lambda l: (int(l.split("\t")[1]), l))


def tsk_fixture(out: Path, name: str, image: Path, offset: int) -> None:
    mft = run_bytes("icat", "-o", str(offset), str(image), "0")
    lines = []
    for number in base_records(mft):
        lines += istat_lines(image, offset, number)
    lines += fls_paths(image, offset)
    save(out, name, mft, lines)


def libfsntfs_fixture(out: Path, plaso_mft: Path) -> None:
    import pyfsntfs

    data = plaso_mft.read_bytes()
    size = struct.unpack_from("<I", data, 0x1C)[0]
    mft = data[:PLASO_RECORDS * size]
    with tempfile.NamedTemporaryFile() as loose:
        loose.write(mft)
        loose.flush()
        reader = pyfsntfs.mft_metadata_file()
        reader.open(loose.name)
        lines = []
        for number in range(reader.number_of_file_entries):
            entry = reader.get_file_entry(number)
            if entry.is_empty() or entry.base_record_file_reference:
                continue
            lines += libfsntfs_lines(number, entry)
        reader.close()
    save(out, "plaso", mft, lines, compress=True)


def libfsntfs_lines(number: int, entry) -> list[str]:
    state = "allocated" if entry.is_allocated() else "deleted"
    kind = "directory" if entry.has_directory_entries_index() else "file"
    si, names, streams, paths = ["-"] * 4, [], [], []
    for index in range(entry.number_of_attributes):
        attribute = entry.get_attribute(index)
        if attribute.attribute_type in (0x10, 0x30):
            times = [iso_from_filetime(getattr(attribute, f"get_{t}_as_integer")())
                     for t in ("creation_time", "modification_time",
                               "entry_modification_time", "access_time")]
        if attribute.attribute_type == 0x10:
            si = times
        elif attribute.attribute_type == 0x30:
            reference = attribute.parent_file_reference
            names.append("\t".join(["N", str(number), str(reference & RECORD_NUMBER_MASK),
                                    str(reference >> 48), "?", "?", *times, attribute.name]))
            hint = path_hint(entry, index)
            if hint and attribute.name_space != 2:  # not a DOS 8.3 alias
                paths.append("\t".join(["P", str(number), hint.lstrip("\\").replace("\\", "/")]))
        elif attribute.attribute_type == 0x80:
            stream = attribute.attribute_name or "-"
            streams.append("\t".join(["S", str(number), stream, "?", str(attribute.data_size)]))
    sequence = str(entry.file_reference >> 48)
    return ["\t".join(["F", str(number), state, kind, sequence, *si]), *names, *streams, *paths]


def path_hint(entry, index: int) -> str | None:
    """libfsntfs's path, or `None` when it can't build one (a parent beyond
    the truncation)."""
    try:
        return entry.get_path_hint(index)
    except OSError:
        return None


def save(out: Path, name: str, mft: bytes, lines: list[str], compress: bool = False) -> None:
    (out / f"{name}.mft.zlib").write_bytes(zlib.compress(mft, 9))
    oracle = "".join(f"{line}\n" for line in lines).encode()
    if compress:
        (out / f"{name}.oracle.zlib").write_bytes(zlib.compress(oracle, 9))
    else:
        (out / f"{name}.oracle").write_bytes(oracle)


def main() -> None:
    plaso_mft = Path(sys.argv[1])
    out = Path(sys.argv[2] if len(sys.argv) > 2 else HERE).resolve()
    os.environ["PATH"] += ":/usr/sbin:/sbin"
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        tsk_fixture(out, "fin-wks-07", HERE.parent / "fin-wks-07.img", 256)
        times = work / "times.img"
        times.write_bytes(zlib.decompress((HERE.parent / "times/ntfs.img.zlib").read_bytes()))
        tsk_fixture(out, "times", times, 0)
        tsk_fixture(out, "deleted", make_deleted_volume(work), 0)
    libfsntfs_fixture(out, plaso_mft)


if __name__ == "__main__":
    main()
