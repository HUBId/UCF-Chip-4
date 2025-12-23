#![forbid(unsafe_code)]

use blake3::Hasher;
use prost::Message;

/// Compute a Blake3 digest with a fully-qualified domain prefix to avoid collisions.
pub fn blake3_digest(domain: &str, schema: &str, version: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(b":");
    hasher.update(schema.as_bytes());
    hasher.update(b":");
    hasher.update(version.as_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Encode a prost message deterministically. Avoid maps to guarantee ordering.
pub fn encode_deterministic<M: Message>(msg: &M) -> Vec<u8> {
    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .expect("prost encoding to Vec should not fail");
    buf
}

/// Digest a prost message after deterministic encoding with a domain separator.
pub fn digest_proto<M: Message>(domain: &str, schema: &str, version: &str, msg: &M) -> [u8; 32] {
    let encoded = encode_deterministic(msg);
    blake3_digest(domain, schema, version, &encoded)
}
