//! 中国移动云盘 (139) storage provider.
//!
//! The 139 API requires the SHA-256 digest of the **whole file**, plus the
//! SHA-256 chaining state at every chunk boundary, when the upload session is
//! created. The Cloudreve server cannot compute them (the file never passes
//! through it), so they have to be produced here and submitted together with
//! the create-session request.
//!
//! Because of that, the chunk size is decided *by the client* before the
//! session exists: it has to be a multiple of the SHA-256 block size (64 bytes)
//! so that every chunk boundary lands on a compressed block, and the file must
//! fit into at most 100 parts (the 139 limit per upload session).

use crate::uploader::chunk::ChunkInfo;
use crate::uploader::session::UploadSession;
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use cloudreve_api::Client as CrClient;
use futures::Stream;
use reqwest::Client as HttpClient;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

/// Minimum chunk size. Also the default for files small enough to fit into
/// [`MAX_PARTS_PER_SESSION`] parts.
pub const MIN_CHUNK_SIZE: u64 = 8 * 1024 * 1024;

/// The 139 API accepts at most 100 parts per upload session (101 returns
/// `04000002 分片信息列表数量不符合标准`).
pub const MAX_PARTS_PER_SESSION: u64 = 100;

/// Size of one SHA-256 compression block.
const SHA256_BLOCK: u64 = 64;

/// Read window used while hashing. Caps memory for very large files, whose
/// chunk size can be hundreds of megabytes.
const HASH_READ_WINDOW: usize = 1024 * 1024;

/// Pick the chunk size for a file of `size` bytes.
///
/// Chunks must be 64-byte aligned (SHA-256 block size) and the file must fit
/// into at most [`MAX_PARTS_PER_SESSION`] parts, so the chunk size grows with
/// the file size.
pub fn pick_chunk_size(size: u64) -> u64 {
    if size <= MIN_CHUNK_SIZE * MAX_PARTS_PER_SESSION {
        return MIN_CHUNK_SIZE;
    }

    let need = size.div_ceil(MAX_PARTS_PER_SESSION);
    need.div_ceil(SHA256_BLOCK) * SHA256_BLOCK
}

/// Number of parts a file is split into. An empty file still yields one part,
/// matching what the server expects for a zero-byte direct upload.
pub fn part_count(size: u64, chunk_size: u64) -> u64 {
    if size == 0 || chunk_size == 0 {
        return 1;
    }
    size.div_ceil(chunk_size)
}

/// Extras required by the 139 create-session request.
#[derive(Debug, Clone)]
pub struct UploadExtras {
    /// Whole-file SHA-256, lowercase hex.
    pub content_hash: String,
    /// Chunk size the hashes were computed with.
    pub chunk_size: u64,
    /// Chaining state after each chunk boundary; entry `i` belongs to part `i+2`.
    pub part_hashes: Vec<[u32; 8]>,
}

/// Hash `path` with the chunking defined by `chunk_size`.
///
/// The file is read twice overall (once here, once while uploading) — the same
/// trade-off the web frontend makes for this policy type.
pub async fn prepare_upload_extras(path: PathBuf, file_size: u64) -> Result<UploadExtras> {
    let chunk_size = pick_chunk_size(file_size);
    let parts = part_count(file_size, chunk_size);

    info!(
        target: "uploader::yun139",
        path = %path.display(),
        file_size,
        chunk_size,
        parts,
        "Computing SHA-256 and per-part hash states for 139 cloud"
    );

    let hash_path = path.clone();
    let (content_hash, part_hashes) =
        tokio::task::spawn_blocking(move || hash_file(&hash_path, file_size, chunk_size))
            .await
            .context("hashing task failed to join")??;

    debug!(
        target: "uploader::yun139",
        path = %path.display(),
        content_hash = %content_hash,
        states = part_hashes.len(),
        "Hash computation finished"
    );

    Ok(UploadExtras {
        content_hash,
        chunk_size,
        part_hashes,
    })
}

/// Blocking hash pass. Runs inside `spawn_blocking`.
fn hash_file(path: &Path, file_size: u64, chunk_size: u64) -> Result<(String, Vec<[u32; 8]>)> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open {} for hashing", path.display()))?;

    let chunk_size_usize = usize::try_from(chunk_size)
        .context("chunk size does not fit into memory")?;
    let mut buf = vec![0u8; HASH_READ_WINDOW.min(chunk_size_usize).max(1)];

    let mut hasher = Sha256Chain::new();
    let parts = part_count(file_size, chunk_size);
    let mut part_hashes = Vec::with_capacity(parts.saturating_sub(1) as usize);
    let mut remaining = file_size;

    for index in 0..parts {
        // Snapshot before feeding part `index`: the state must cover the
        // completed prefix only, and it does since every part except the last
        // is a multiple of the block size.
        if index > 0 {
            part_hashes.push(hasher.snapshot().with_context(|| {
                format!("hash state is not block aligned before part {index}")
            })?);
        }

        let mut left = chunk_size.min(remaining);
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            file.read_exact(&mut buf[..want]).with_context(|| {
                format!(
                    "failed to read {} bytes at part {index} (file truncated?)",
                    want
                )
            })?;
            hasher.update(&buf[..want]);
            left -= want as u64;
        }
        remaining -= chunk_size.min(remaining);
    }

    Ok((to_hex(&hasher.finalize()), part_hashes))
}

/// Upload one chunk to the presigned 139 object storage URL.
///
/// Identical to the S3-like providers: a plain `PUT` with an exact
/// `Content-Length`, so the implementation is shared.
pub async fn upload_chunk_generic<S>(
    http_client: &HttpClient,
    chunk: &ChunkInfo,
    stream: S,
    session: &UploadSession,
) -> Result<Option<String>>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + Sync + Unpin + 'static,
{
    super::s3::upload_chunk_s3_generic(http_client, chunk, stream, session).await
}

/// Finish the upload: notify Cloudreve so it can assemble the object on the
/// 139 side (`/hcy/file/complete` with the content hash).
pub async fn complete_upload(cr_client: &Arc<CrClient>, session: &UploadSession) -> Result<()> {
    super::s3::callback_s3like(cr_client, session, "yun139").await
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Incremental SHA-256 that can export its raw chaining state.
///
/// The `sha2` crate does not expose the internal state, and the 139 API needs
/// `SHA256_CTX.h[0..7]` at chunk boundaries, so the compression function is
/// implemented here. It is verified against `sha2` in the unit tests below.
pub struct Sha256Chain {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[rustfmt::skip]
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Default for Sha256Chain {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Chain {
    pub fn new() -> Self {
        Self {
            h: SHA256_IV,
            buf: [0u8; 64],
            buf_len: 0,
            total: 0,
        }
    }

    /// Feed bytes into the hasher.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];

            if self.buf_len == 64 {
                let block = self.buf;
                compress256(&mut self.h, &block);
                self.buf_len = 0;
            }
        }

        while data.len() >= 64 {
            compress256(&mut self.h, &data[..64]);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Export the raw chaining state.
    ///
    /// Only valid when the hasher is block aligned (no pending bytes), which
    /// holds at chunk boundaries for chunk sizes that are multiples of 64.
    pub fn snapshot(&self) -> Result<[u32; 8]> {
        if self.buf_len != 0 {
            bail!(
                "SHA-256 state is not block aligned ({} pending bytes); \
                 choose a chunk size that is a multiple of 64",
                self.buf_len
            );
        }
        Ok(self.h)
    }

    /// Finish hashing and return the 32-byte digest.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total.wrapping_mul(8);

        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        self.update(&bit_len.to_be_bytes());

        let mut out = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn compress256(state: &mut [u32; 8], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);

    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
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

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
    }

    fn chain_hex(data: &[u8]) -> String {
        let mut hasher = Sha256Chain::new();
        hasher.update(data);
        to_hex(&hasher.finalize())
    }

    #[test]
    fn digest_matches_reference() {
        for len in [
            0usize, 1, 3, 55, 56, 57, 63, 64, 65, 127, 128, 129, 1000, 8192,
        ] {
            let data = sample(len);
            let want = format!("{:x}", Sha256::digest(&data));
            assert_eq!(chain_hex(&data), want, "mismatch at len={len}");
        }
    }

    #[test]
    fn digest_matches_reference_when_fed_in_odd_pieces() {
        let data = sample(1000);
        let want = format!("{:x}", Sha256::digest(&data));

        for step in [1usize, 7, 63, 64, 65, 129] {
            let mut hasher = Sha256Chain::new();
            for piece in data.chunks(step) {
                hasher.update(piece);
            }
            assert_eq!(to_hex(&hasher.finalize()), want, "mismatch at step={step}");
        }
    }

    #[test]
    fn snapshot_requires_block_alignment() {
        let mut hasher = Sha256Chain::new();
        hasher.update(&sample(32));
        assert!(hasher.snapshot().is_err(), "unaligned state must be rejected");

        let mut hasher = Sha256Chain::new();
        hasher.update(&sample(128));
        assert_eq!(hasher.snapshot().unwrap().len(), 8);
    }

    #[test]
    fn snapshot_then_continue_matches_reference() {
        // 3 blocks: snapshot after block 1 and block 2, then finish.
        let data = sample(192);
        let want = format!("{:x}", Sha256::digest(&data));

        let mut hasher = Sha256Chain::new();
        hasher.update(&data[..64]);
        hasher.snapshot().unwrap();
        hasher.update(&data[64..128]);
        hasher.snapshot().unwrap();
        hasher.update(&data[128..]);

        assert_eq!(to_hex(&hasher.finalize()), want);
    }

    #[test]
    fn pick_chunk_size_respects_api_limits() {
        for size in [
            0u64,
            1,
            1024 * 1024,
            MIN_CHUNK_SIZE,
            MIN_CHUNK_SIZE * MAX_PARTS_PER_SESSION,
            MIN_CHUNK_SIZE * MAX_PARTS_PER_SESSION + 1,
            2 * 1024 * 1024 * 1024,
            10 * 1024 * 1024 * 1024,
        ] {
            let chunk = pick_chunk_size(size);
            assert_eq!(chunk % SHA256_BLOCK, 0, "chunk not aligned for size={size}");
            assert!(chunk >= MIN_CHUNK_SIZE, "chunk too small for size={size}");

            let parts = part_count(size, chunk);
            assert!(
                parts <= MAX_PARTS_PER_SESSION,
                "size={size} yields {parts} parts of {chunk} bytes"
            );
            assert!(parts >= 1);
        }
    }

    #[test]
    fn part_count_handles_empty_file() {
        assert_eq!(part_count(0, MIN_CHUNK_SIZE), 1);
        assert_eq!(part_count(MIN_CHUNK_SIZE, MIN_CHUNK_SIZE), 1);
        assert_eq!(part_count(MIN_CHUNK_SIZE + 1, MIN_CHUNK_SIZE), 2);
    }
}
