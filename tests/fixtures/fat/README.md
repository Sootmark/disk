FAT12, FAT16, FAT32 and exFAT volumes written for these tests on Linux
(`mkfs.fat`, `mkfs.exfat`, then mounted): long names with accents, nested
folders, files deleted between others so later files fragment, an empty
file. Stored zlib-compressed. `<volume>.sha256` is The Sleuth Kit's reading
(`fls -r -p -u -F`, then `icat`): every allocated file and its SHA-256.
