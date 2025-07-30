use rand::{Rng, distr::Alphanumeric};
use sha2::{Digest, Sha256};

pub fn generate_verification_token() -> (String, String) {
    let token = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect::<String>();

    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());

    let hash = format!("{:x}", hasher.finalize());
    (token, hash)
}

pub fn gen_hash_from_token(val: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(val.as_bytes());

    format!("{:x}", hasher.finalize())
}
