//! LZNT1, the compression NTFS applies to compressed files ([MS-XCA]
//! §2.5): a compression unit is a series of chunks of up to 4 KiB, each a
//! 2-byte header (size, and whether it's compressed) then either the raw
//! bytes or flag bytes each announcing eight literals or back-references.
//! A back-reference packs a displacement and a length into 16 bits, split
//! according to how far into the chunk it is.

use std::io;

const CHUNK: usize = 4096;
/// Header bit: the chunk is compressed (else stored).
const COMPRESSED: u16 = 0x8000;

fn corrupt(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("LZNT1: {reason}"))
}

/// Decompress one compression unit into `out`, up to `limit` bytes.
///
/// # Errors
/// On a malformed chunk or a back-reference before its chunk's start.
pub(crate) fn decompress(input: &[u8], limit: usize, out: &mut Vec<u8>) -> io::Result<()> {
    let start = out.len();
    let mut at = 0;
    while at + 2 <= input.len() && out.len() - start < limit {
        let header = u16::from_le_bytes([input[at], input[at + 1]]);
        if header == 0 {
            break;
        }
        let size = usize::from(header & 0x0fff) + 1;
        let body = input
            .get(at + 2..at + 2 + size)
            .ok_or_else(|| corrupt("chunk past the end of the unit"))?;
        at += 2 + size;
        if header & COMPRESSED == 0 {
            out.extend_from_slice(body);
        } else {
            chunk(body, out)?;
        }
    }
    out.truncate(start + limit.min(out.len() - start));
    Ok(())
}

/// One compressed chunk.
fn chunk(body: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    let chunk_start = out.len();
    let mut at = 0;
    while at < body.len() {
        let flags = body[at];
        at += 1;
        for bit in 0..8 {
            if at >= body.len() {
                break;
            }
            if flags & (1 << bit) == 0 {
                out.push(body[at]);
                at += 1;
                continue;
            }
            let token = u16::from_le_bytes([
                body[at],
                *body
                    .get(at + 1)
                    .ok_or_else(|| corrupt("truncated reference"))?,
            ]);
            at += 2;
            let position = out.len() - chunk_start;
            if position == 0 {
                return Err(corrupt("reference at the start of a chunk"));
            }
            // The further into the chunk, the more bits for displacement.
            let mut length_bits = 12;
            let mut p = position - 1;
            while p >= 0x10 {
                p >>= 1;
                length_bits -= 1;
            }
            let length = usize::from(token & ((1 << length_bits) - 1)) + 3;
            let displacement = usize::from(token >> length_bits) + 1;
            if displacement > position {
                return Err(corrupt("reference before the chunk"));
            }
            if position + length > CHUNK {
                return Err(corrupt("chunk longer than 4 KiB"));
            }
            let from = out.len() - displacement;
            // Byte by byte: a reference may overlap what it produces.
            for i in 0..length {
                let byte = out[from + i];
                out.push(byte);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored chunk, then a compressed one: "abc" and a reference
    /// repeating it (displacement 3, length 6) as "abcabcabc".
    #[test]
    fn stored_and_compressed_chunks() {
        let mut unit = Vec::new();
        unit.extend_from_slice(&(0x3000u16 | 2).to_le_bytes());
        unit.extend_from_slice(b"xyz");
        // Flags 0b1000: three literals, then a reference. At position 3,
        // 12 length bits: displacement 3 → 2 << 12, length 6 → 3.
        let token: u16 = (2 << 12) | 3;
        let body = [0b1000, b'a', b'b', b'c', token as u8, (token >> 8) as u8];
        unit.extend_from_slice(&(0xb000u16 | (body.len() as u16 - 1)).to_le_bytes());
        unit.extend_from_slice(&body);
        let mut out = Vec::new();
        decompress(&unit, 4096, &mut out).unwrap();
        assert_eq!(out, b"xyzabcabcabc");
    }

    #[test]
    fn bad_references_are_errors() {
        let token: u16 = 5 << 12;
        let body = [0b10, b'a', token as u8, (token >> 8) as u8];
        let mut unit = (0xb000u16 | (body.len() as u16 - 1)).to_le_bytes().to_vec();
        unit.extend_from_slice(&body);
        assert!(decompress(&unit, 4096, &mut Vec::new()).is_err());
    }

    proptest::proptest! {
        /// Any bytes decompress or fail: never a panic, never past the limit.
        #[test]
        fn arbitrary_units_never_panic(unit in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..9000)) {
            let mut out = Vec::new();
            if decompress(&unit, 65_536, &mut out).is_ok() {
                proptest::prop_assert!(out.len() <= 65_536);
            }
        }
    }
}
