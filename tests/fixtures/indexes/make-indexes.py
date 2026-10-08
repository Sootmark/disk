#!/usr/bin/env python3
"""Recreate the directory index fixture and what The Sleuth Kit reads in it.

    sudo python3 make-indexes.py [out_dir]      (default: this directory)

Linux only (loop mounts): ntfs-3g, sleuthkit. No real data: every file is a
placeholder written here.

`indexes.img.zlib` is an 8 MiB NTFS volume written with ntfs-3g
(zlib-compressed for the repository):

- `docs`: 300 reports, written between the larger files of `filler` so
  its index blocks are scattered (12 runs), then 40 deleted (their entries
  linger in the blocks' slack);
- `Users/alice/Documents`: long names, one or two index blocks;
- `emptied`: 80 files, all deleted since: the index keeps its blocks;
- `small`: three files, an index that fits in its record (none listed);
- the root, whose index outgrew its record too.

`indexes.oracle` lists every directory's `$INDEX_ALLOCATION:$I30`, one per
line, tab-separated:

    record  attribute_id  size  sha256  path

as `istat` (size) and `icat <image> <record>-160-<id>` (bytes) give it;
`path` is `/`-separated from the root (empty for the root itself).
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT_RECORD = 5


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


def write(root: Path, relative: str, content: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def make_volume(work: Path) -> Path:
    image = work / "indexes.img"
    image.write_bytes(b"")
    os.truncate(image, 8 << 20)
    run("mkfs.ntfs", "-q", "-F", "-f", "-s", "512", "-c", "4096", "-L", "INDEXES", str(image))
    with Mount(image) as root:
        for i in range(1, 301):
            write(root, f"docs/report_{i:03}.txt", f"report {i} (placeholder)\n".encode())
            if i % 25 == 0:
                write(root, f"filler/block_{i:03}.bin", bytes([i % 256]) * 12288)
        for i in range(1, 61):
            name = f"Users/alice/Documents/meeting-notes-for-the-quarterly-review-{i:02}.txt"
            write(root, name, b"notes (placeholder)\n")
        for i in range(1, 81):
            write(root, f"emptied/staged_{i:02}.tmp", b"staged (placeholder)\n")
        for name in ["a.txt", "b.txt", "c.txt"]:
            write(root, f"small/{name}", b"small (placeholder)\n")
        for i in range(1, 31):
            write(root, f"top-level-file-{i:02}.txt", b"top (placeholder)\n")
    with Mount(image) as root:
        for i in [*range(50, 70), *range(200, 220)]:
            (root / f"docs/report_{i:03}.txt").unlink()
        for path in (root / "emptied").iterdir():
            path.unlink()
    return image


def directories(image: Path) -> list[tuple[int, str]]:
    found = [(ROOT_RECORD, "")]
    for line in run("fls", "-r", "-p", "-D", str(image)).splitlines():
        match = re.fullmatch(r"d/d (\d+)-\d+-\d+:\t(.+)", line)
        if match:
            found.append((int(match[1]), match[2]))
    return found


def oracle(image: Path) -> str:
    lines = []
    for record, path in directories(image):
        istat = run("istat", str(image), str(record))
        for match in re.finditer(
            r"Type: \$INDEX_ALLOCATION \(160-(\d+)\)\s+Name: \$I30\s+Non-Resident\s+size: (\d+)",
            istat,
        ):
            attribute, size = match[1], int(match[2])
            content = run_bytes("icat", str(image), f"{record}-160-{attribute}")
            assert len(content) == size, (path, len(content), size)
            digest = hashlib.sha256(content).hexdigest()
            lines.append(f"{record}\t{attribute}\t{size}\t{digest}\t{path}")
    return "\n".join(sorted(lines, key=lambda line: line.split("\t")[4])) + "\n"


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE
    with tempfile.TemporaryDirectory() as work:
        image = make_volume(Path(work))
        (out / "indexes.oracle").write_text(oracle(image))
        (out / "indexes.img.zlib").write_bytes(zlib.compress(image.read_bytes(), 9))


if __name__ == "__main__":
    main()
