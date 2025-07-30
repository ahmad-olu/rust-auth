use rand::{Rng, distr::Alphanumeric};

pub fn generate_verification_token() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}
