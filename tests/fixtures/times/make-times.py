#!/usr/bin/env python3
"""Recreate the timestamp fixtures: small NTFS, FAT12 and exFAT volumes
whose files carry known times, and what independent readers make of them.

    sudo python3 make-times.py [out_dir]      (default: this directory)

Linux only (loop mounts): ntfs-3g, dosfstools, exfatprogs, sleuthkit.
No real data: every file is a placeholder written here.

For each volume, `<volume>.img.zlib` is the image (zlib-compressed for the
repository) and `<volume>.times` the oracle, one line per file:

    path<TAB>created<TAB>modified<TAB>changed<TAB>accessed

each time as `YYYY-MM-DDTHH:MM:SS.fffffff` in UTC (`-` when the file system
has no such time):

- NTFS: The Sleuth Kit's `istat` ($STANDARD_INFORMATION), checked against
  ntfs-3g's reading (`system.ntfs_times`) for the files written here.
  Times are set through ntfs-3g; MFT-entry-modified is the write time.
  mkfs.ntfs leaves $MFT's times zero (not set).
- FAT12: the Linux kernel's reading (`stat` on the volume mounted with
  `tz=UTC`, so wall-clock times read as written), checked against `istat`
  to the second. Creation is the write time (with its 10 ms field).
- exFAT: the kernel's reading (mounted with `time_offset=0`). The kernel
  writes every time with a valid UTC offset of zero; three files are then
  patched (entry-set checksums recomputed, `fsck.exfat` must pass) to carry
  +02:00, -05:00, and no valid offset (local time, zone unknown, which
  reads as written). The Sleuth Kit (4.12) ignores the offsets, so it
  isn't the oracle here.
"""

import os
import re
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

FILETIME_UNIX_OFFSET = 116_444_736_000_000_000
# How `istat` prints a zero FILETIME (not set): 0 minus the 1601-to-1970
# offset, wrapped in 64 bits, divided to seconds, then cut to 32 bits.
TSK_ZERO_FILETIME = "2076-11-29T08:54:34.0000000"


def run(*args: str, **kwargs) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout


def touch(path: Path, when: str, access_only: bool = False) -> None:
    run("touch", *(["-a"] if access_only else []), "-d", when, str(path))


def iso_from_stat(text: str) -> str:
    """`2021-03-04 05:06:06.890000000 +0000` -> `2021-03-04T05:06:06.8900000`."""
    match = re.fullmatch(r"(\S+) (\d\d:\d\d:\d\d)\.(\d{7})\d* \+0000", text.strip())
    if not match:
        raise SystemExit(f"unexpected stat time: {text!r}")
    return f"{match[1]}T{match[2]}.{match[3]}"


def iso_from_istat(text: str) -> str:
    """`2001-09-09 01:46:40.123456700 (UTC)` -> `2001-09-09T01:46:40.1234567`."""
    match = re.fullmatch(r"(\S+) (\d\d:\d\d:\d\d)(?:\.(\d{7})\d*)? \(UTC\)", text.strip())
    if not match:
        raise SystemExit(f"unexpected istat time: {text!r}")
    return f"{match[1]}T{match[2]}.{match[3] or '0000000'}"


def iso_from_filetime(value: int) -> str:
    ticks = value - FILETIME_UNIX_OFFSET
    seconds, fraction = divmod(ticks, 10_000_000)
    stamp = run("date", "-u", "-d", f"@{seconds}", "+%Y-%m-%dT%H:%M:%S").strip()
    return f"{stamp}.{fraction:07d}"


def filetime(when: str, ticks: int = 0) -> int:
    seconds = int(run("date", "-u", "-d", when, "+%s"))
    return seconds * 10_000_000 + FILETIME_UNIX_OFFSET + ticks


def fls_files(image: Path) -> list[tuple[str, int]]:
    """Allocated files (and streams) with their MFT entry or inode number."""
    out = []
    for line in run("fls", "-r", "-p", "-u", "-F", str(image)).splitlines():
        kind_and_address, path = line.split("\t", 1)
        if kind_and_address.startswith(("v/v", "V/V")) or path.endswith("(Volume Label Entry)"):
            continue  # TSK's virtual files ($MBR, $FAT1, ...) and FAT labels
        address = int(re.search(r"(\d+)", kind_and_address.split()[-1])[1])
        out.append((path, address))
    return out


def istat_times(image: Path, address: int) -> dict[str, str]:
    """The first block of times `istat` prints: $STANDARD_INFORMATION on
    NTFS, the directory entry on FAT. `-` for a zero FILETIME."""
    labels = {"Created", "File Modified", "MFT Modified", "Accessed", "Written"}
    times: dict[str, str] = {}
    for line in run("istat", "-z", "UTC", str(image), str(address)).splitlines():
        label, _, value = line.partition(":\t")
        if label in labels and label not in times:
            iso = iso_from_istat(value)
            times[label] = "-" if iso == TSK_ZERO_FILETIME else iso
    return times


class Mount:
    def __init__(self, image: Path, fstype: str, options: str):
        self.image, self.fstype, self.options = image, fstype, options
        self.point = Path(tempfile.mkdtemp())

    def __enter__(self) -> Path:
        run("mount", "-t", self.fstype, "-o", f"loop,{self.options}", str(self.image), str(self.point))
        return self.point

    def __exit__(self, *_) -> None:
        run("umount", str(self.point))
        self.point.rmdir()


def write(root: Path, relative: str, content: bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def save(out: Path, volume: str, image: Path, lines: list[str]) -> None:
    (out / f"{volume}.img.zlib").write_bytes(zlib.compress(image.read_bytes(), 9))
    (out / f"{volume}.times").write_text("".join(f"{line}\n" for line in sorted(lines)))


# ==================================================================== NTFS ===

NTFS_SET = {
    # path: (created, modified, accessed) through ntfs-3g's system.ntfs_times.
    "report.txt": (
        filetime("2001-09-09 01:46:40", 1_234_567),
        filetime("2004-11-09 11:33:20", 2),
        filetime("2008-01-10 21:20:00", 9_999_999),
    ),
}


def make_ntfs(work: Path, out: Path) -> None:
    image = work / "ntfs.img"
    image.write_bytes(b"")
    os.truncate(image, 2 << 20)
    run("mkfs.ntfs", "-q", "-F", "-f", "-s", "512", "-c", "4096", "-L", "TIMES", str(image))
    with Mount(image, "ntfs-3g", "rw") as root:
        report = write(root, "report.txt", b"Quarterly figures (placeholder).\n")
        os.setxattr(report, "user.Zone.Identifier", b"[ZoneTransfer]\r\nZoneId=3\r\n")
        log = write(root, "logs/app.log", b"started\n" * 600)  # non-resident
        touch(log, "2023-06-15 08:30:00.5")
        for path, (created, modified, accessed) in NTFS_SET.items():
            os.setxattr(root / path, "system.ntfs_times",
                        struct.pack("<4Q", created, modified, accessed, 0))
    with Mount(image, "ntfs-3g", "ro") as root:
        third_party = {
            path: struct.unpack("<4Q", os.getxattr(root / path, "system.ntfs_times"))
            for path in [*NTFS_SET, "logs/app.log"]
        }
    lines = []
    for path, address in fls_files(image):
        t = istat_times(image, address)
        times = [t["Created"], t["File Modified"], t["MFT Modified"], t["Accessed"]]
        base = path.split(":")[0]
        if base in third_party:
            created, modified, accessed, changed = third_party[base]
            ntfs_3g = [iso_from_filetime(v) for v in (created, modified, changed, accessed)]
            if ntfs_3g != times:
                raise SystemExit(f"{path}: istat {times} != ntfs-3g {ntfs_3g}")
        lines.append("\t".join([path, *times]))
    save(out, "ntfs", image, lines)


# =================================================================== FAT12 ===

def make_fat12(work: Path, out: Path) -> None:
    image = work / "fat12.img"
    image.write_bytes(b"")
    os.truncate(image, 1 << 20)
    run("mkfs.fat", "-F", "12", "-n", "TIMES", str(image))
    with Mount(image, "vfat", "rw,tz=UTC") as root:
        report = write(root, "Quarterly Report.docx", b"placeholder\n")
        touch(report, "2021-03-04 05:06:07.89")  # odd second: stored as :06
        touch(report, "2022-01-02 23:59:59", access_only=True)  # a date only
        touch(write(root, "NOTES.TXT", b"notes\n"), "1999-12-31 23:59:58")
        touch(write(root, "Archive/old.txt", b"old\n"), "1980-01-01 00:00:00")
    lines = []
    with Mount(image, "vfat", "ro,tz=UTC") as root:
        for path, address in fls_files(image):
            created, modified, accessed = (
                iso_from_stat(v)
                for v in run("stat", "-c", "%w|%y|%x", str(root / path)).split("|")
            )
            tsk = istat_times(image, address)
            for ours, theirs in [(created, tsk["Created"]), (modified, tsk["Written"]),
                                 (accessed, tsk["Accessed"])]:
                if ours[:19] != theirs[:19]:
                    raise SystemExit(f"{path}: kernel {ours} != istat {theirs}")
            lines.append("\t".join([path, created, modified, "-", accessed]))
    save(out, "fat12", image, lines)


# =================================================================== exFAT ===

EXFAT_OFFSETS = {
    # file name: UTC offset byte written to its three timestamps
    "plus-two.txt": 0x80 | 8,  # valid, +8 quarter hours
    "minus-five.txt": 0x80 | (-20 & 0x7F),  # valid, -20 quarter hours
    "no-zone.txt": 0x00,  # not valid: local time, zone unknown
}


def entry_set_checksum(entries: bytes) -> int:
    checksum = 0
    for index, byte in enumerate(entries):
        if index in (2, 3):
            continue
        checksum = (((checksum & 1) << 15) + (checksum >> 1) + byte) & 0xFFFF
    return checksum


def patch_exfat_offsets(image: Path) -> None:
    data = bytearray(image.read_bytes())
    sector = 1 << data[108]
    cluster = sector << data[109]
    heap = struct.unpack_from("<I", data, 88)[0] * sector
    root = struct.unpack_from("<I", data, 96)[0]
    at = heap + (root - 2) * cluster
    directory = range(at, at + cluster, 32)  # the root fits one cluster here
    patched = set()
    for offset in directory:
        if data[offset] != 0x85:
            continue
        count = data[offset + 1]
        entries = [offset + 32 * i for i in range(count + 1)]
        name_length = data[entries[1] + 3]
        name = b"".join(data[e + 2:e + 32] for e in entries[2:]).decode("utf-16-le")[:name_length]
        if name not in EXFAT_OFFSETS:
            continue
        data[offset + 22:offset + 25] = bytes([EXFAT_OFFSETS[name]] * 3)
        whole = bytes(data[offset:offset + 32 * (count + 1)])
        struct.pack_into("<H", data, offset + 2, entry_set_checksum(whole))
        patched.add(name)
    if patched != set(EXFAT_OFFSETS):
        raise SystemExit(f"exFAT: patched only {patched}")
    image.write_bytes(data)


def make_exfat(work: Path, out: Path) -> None:
    image = work / "exfat.img"
    image.write_bytes(b"")
    os.truncate(image, 3 << 20)
    run("mkfs.exfat", "-L", "TIMES", str(image))
    with Mount(image, "exfat", "rw") as root:
        for name in ["utc.txt", *EXFAT_OFFSETS]:
            touch(write(root, name, f"{name}\n".encode()), "2021-03-04 05:06:07.89")
        touch(write(root, "Folder/deep.txt", b"deep\n"), "2024-02-29 12:00:01.5")
    patch_exfat_offsets(image)
    run("fsck.exfat", "-n", str(image))
    lines = []
    with Mount(image, "exfat", "ro,time_offset=0") as root:
        for path, _ in fls_files(image):
            if path.startswith("$"):
                continue  # TSK's names for the bitmap, up-case table, label
            created, modified, accessed = (
                iso_from_stat(v)
                for v in run("stat", "-c", "%w|%y|%x", str(root / path)).split("|")
            )
            lines.append("\t".join([path, created, modified, "-", accessed]))
    save(out, "exfat", image, lines)


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent).resolve()
    os.environ["PATH"] += ":/usr/sbin:/sbin"
    os.environ["TZ"] = "UTC"  # touch, date and stat read and print UTC
    with tempfile.TemporaryDirectory() as work:
        make_ntfs(Path(work), out)
        make_fat12(Path(work), out)
        make_exfat(Path(work), out)


if __name__ == "__main__":
    main()
