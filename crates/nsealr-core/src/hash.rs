//! SHA-256 one-shot hashing.
//!
//! Ported from the C++ reference `host_core` sources `src/sha256.cpp` +
//! `include/nsealr/sha256.hpp`. The C++ surface is a single one-shot
//! `sha256_hex(std::string_view) -> std::string` — there is no incremental /
//! streaming API — so this port mirrors that shape: [`sha256`] returns the raw
//! 32-byte digest and [`sha256_hex`] returns the same lowercase-hex encoding the
//! C++ produced, as a fixed 64-byte ASCII array so the crate stays `no_std` and
//! allocation-free. The algorithm (initial hash values, round constants,
//! big-endian word order, and the `len % 64 == 56` padding rule) matches the
//! C++ byte-for-byte.

/// SHA-256 initial hash values (first 32 bits of the fractional parts of the
/// square roots of the first eight primes).
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 round constants (first 32 bits of the fractional parts of the cube
/// roots of the first sixty-four primes).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Processes one 64-byte message block into the running state.
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for (&k, &word) in K.iter().zip(w.iter()) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(k)
            .wrapping_add(word);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// An incremental SHA-256 hasher. Added in M-T3.6 so the review layer can hash
/// the canonical approval payload as it is generated, instead of materialising
/// the whole (multi-KiB) JSON in RAM the way the C++ concatenated a heap
/// `std::string` before its one-shot `sha256_hex` call — the digest over the
/// same bytes is identical by construction ([`sha256`] itself is implemented on
/// top of this state, so the M-T3.1 known-answer vectors pin both paths).
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    total_len: u64,
}

impl Sha256 {
    /// Creates a fresh hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: H0,
            buffer: [0; 64],
            buffered: 0,
            total_len: 0,
        }
    }

    /// Absorbs `input` into the running state.
    pub fn update(&mut self, input: &[u8]) {
        self.total_len = self.total_len.wrapping_add(input.len() as u64);
        let mut rest = input;
        if self.buffered > 0 {
            let take = rest.len().min(64 - self.buffered);
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            if self.buffered < 64 {
                // The whole input fit into the partial block.
                return;
            }
            let block = self.buffer;
            compress(&mut self.state, &block);
            self.buffered = 0;
        }
        let mut blocks = rest.chunks_exact(64);
        for block in blocks.by_ref() {
            let mut full = [0u8; 64];
            full.copy_from_slice(block);
            compress(&mut self.state, &full);
        }
        let remainder = blocks.remainder();
        self.buffer[..remainder.len()].copy_from_slice(remainder);
        self.buffered = remainder.len();
    }

    /// Finalizes the hash, returning the raw 32-byte digest. Appends 0x80, pads
    /// with zeros up to `len % 64 == 56`, then the 64-bit big-endian bit
    /// length, spilling into a second block when the buffered remainder leaves
    /// no room (remainder length >= 56).
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.total_len.wrapping_mul(8);
        let mut tail = [0u8; 128];
        tail[..self.buffered].copy_from_slice(&self.buffer[..self.buffered]);
        tail[self.buffered] = 0x80;
        let tail_blocks = if self.buffered < 56 { 1 } else { 2 };
        let filled = tail_blocks * 64;
        tail[filled - 8..filled].copy_from_slice(&bit_length.to_be_bytes());
        let mut first = [0u8; 64];
        first.copy_from_slice(&tail[..64]);
        compress(&mut self.state, &first);
        if tail_blocks == 2 {
            let mut second = [0u8; 64];
            second.copy_from_slice(&tail[64..128]);
            compress(&mut self.state, &second);
        }

        let mut digest = [0u8; 32];
        for (word, slot) in self.state.iter().zip(digest.chunks_exact_mut(4)) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// Finalizes the hash as 64 lowercase ASCII hex bytes (the [`sha256_hex`]
    /// encoding).
    #[must_use]
    pub fn finalize_hex(self) -> [u8; 64] {
        to_hex(self.finalize())
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes a raw digest as 64 lowercase ASCII hex bytes.
fn to_hex(digest: [u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (byte, slot) in digest.iter().zip(out.chunks_exact_mut(2)) {
        slot[0] = HEX[usize::from(byte >> 4)];
        slot[1] = HEX[usize::from(byte & 0x0f)];
    }
    out
}

/// Computes the SHA-256 digest of `input`, returning the raw 32 bytes.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize()
}

/// Computes the SHA-256 digest of `input` and returns it as 64 lowercase ASCII
/// hex bytes, matching the string the C++ `sha256_hex` produced.
pub fn sha256_hex(input: &[u8]) -> [u8; 64] {
    to_hex(sha256(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_hex(input: &[u8], expected: &str) {
        let out = sha256_hex(input);
        assert_eq!(core::str::from_utf8(&out).unwrap(), expected);
    }

    #[test]
    fn nist_known_answer_vectors() {
        assert_hex(
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_hex(
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        // 448-bit (56-byte) two-block NIST message.
        assert_hex(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
        // 896-bit (112-byte) NIST message.
        assert_hex(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        );
    }

    #[test]
    fn block_boundary_padding_paths() {
        // 55 bytes: 0x80 + length fit in the same (single) final block.
        assert_hex(
            &[b'a'; 55],
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
        );
        // 56 bytes: padding forces a second final block.
        assert_hex(
            &[b'a'; 56],
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
        );
        // Exactly one full 64-byte block, then a whole padding block.
        assert_hex(
            &[b'a'; 64],
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        );
        // Long multi-block input.
        assert_hex(
            &[b'a'; 1000],
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
        );
    }

    #[test]
    fn raw_digest_bytes() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ],
        );
        let abc = sha256(b"abc");
        assert_eq!(abc[0], 0xba);
        assert_eq!(abc[31], 0xad);
    }

    // The incremental hasher matches the one-shot digest for every chunking of
    // the same input, including chunks that straddle block boundaries (M-T3.6
    // addition; the KATs above already pin the shared compression path).
    #[test]
    fn incremental_updates_match_one_shot() {
        let input: std::vec::Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let expected = sha256(&input);
        for chunk_size in [1usize, 3, 55, 56, 63, 64, 65, 128, 999] {
            let mut hasher = Sha256::new();
            for chunk in input.chunks(chunk_size) {
                hasher.update(chunk);
            }
            assert_eq!(hasher.finalize(), expected);
        }
        let mut hex_hasher = Sha256::default();
        hex_hasher.update(b"abc");
        assert_eq!(
            core::str::from_utf8(&hex_hasher.finalize_hex()).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        let empty = Sha256::new();
        assert_eq!(
            core::str::from_utf8(&empty.finalize_hex()).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    // Byte-for-byte cross-primitive parity with a READ-ONLY specs/vectors
    // fixture: specs/vectors/transports/qr-animated-response-kind-1-basic.json
    // asserts `decoded_json_sha256 == sha256(base64url_decode(payload_base64url))`.
    // Both literals are copied verbatim from that fixture.
    #[test]
    fn specs_vector_sha256_over_decoded_base64url_payload() {
        const PAYLOAD: &[u8] = b"eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm9rIjp0cnVlLCJyZXN1bHQiOnsiZXZlbnQiOnsiaWQiOiIyOTc3ZjEwN2FkMjY2OGRiZDlmMDliODU5NGVmZjNiNTI3NmUyMWJmZTA5OGU2MGFlM2U5MDVlM2M4NjFlNGQzIiwicHVia2V5IjoiNGYzNTViZGNiN2NjMGFmNzI4ZWYzY2NlYjk2MTVkOTA2ODRiYjViMmNhNWY4NTlhYjBmMGI3MDQwNzU4NzFhYSIsImNyZWF0ZWRfYXQiOjE3MTAwMDAwMDAsImtpbmQiOjEsInRhZ3MiOltdLCJjb250ZW50IjoiblNlYWxyIGZpeHR1cmU6IGJhc2ljIGtpbmQgMSBldmVudC4iLCJzaWciOiIyZWVjMDM1MWViMWQ2NTExNDA5MjJkNGIxZjFiZDgxMzVmNDQ3NGFhYmY0MmVjNWJkYTcwMTEwODdjMWEwNzJkNzFiZTg2MzY0NmRjMTYyZTRkOTZlYWNmMTRhZmVlZDI2MThhNGFjYjBlMTEzNGEyNzNhMmI4ZTczMDM5ZTY1NCJ9fX0";
        const EXPECTED: &str = "e4ed45466ba40f9e902bf988eb5aab58082b17586b0da47f45f67ce0a4211ec3";
        let mut raw = [0u8; 512];
        let decoded = crate::base64url::decode_base64url(PAYLOAD, &mut raw).expect("decode fits");
        let hex = sha256_hex(decoded);
        assert_eq!(core::str::from_utf8(&hex).unwrap(), EXPECTED);
    }
}
