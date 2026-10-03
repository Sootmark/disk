Loose `$MFT` files, zlib-compressed, each with what an independent reader
sees in it (`<name>.oracle`): recreated, and their format described, by
`make-mft.py`.

`plaso.mft.zlib` is the first 6000 records of `test_data/MFT` from
[plaso](https://github.com/log2timeline/plaso) (commit e105c77d), under the
Apache License 2.0 (`LICENSE-plaso`); `plaso.oracle.zlib` is libfsntfs's
reading of it. The other files are placeholders written for these tests.
