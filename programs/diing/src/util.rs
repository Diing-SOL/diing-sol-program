use hex_literal::hex;
use sha2::{Digest, Sha256};

fn verify(plaintxt: &str, ciphertxt: [u8; 32]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(plaintxt);
    let result = hasher.finalize();
    let result = result.as_slice();
    result == ciphertxt
}
