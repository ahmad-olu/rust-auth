use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};

use crate::errors::{Error, Result};

pub fn hash(password: &[u8]) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2.hash_password(password, &salt)?.to_string())
}
pub fn validate(password: &[u8], hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();

    match argon2.verify_password(password, &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(Error::Argon2Error(e)),
    }
}

pub fn validate_strict(password: &[u8], hash: &str) -> Result<()> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    let res = argon2.verify_password(password, &parsed_hash)?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_validate() {
        let password = b"my_secure_password";

        // Hash the password
        let hashed = hash(password).expect("Failed to hash password");
        println!("Hashed password: {}", hashed);

        // Validate with correct password
        assert!(validate(password, &hashed).expect("Validation failed"));

        // Validate with incorrect password
        let wrong_password = b"wrong_password";
        assert!(!validate(wrong_password, &hashed).expect("Validation failed"));
    }

    #[test]
    fn test_validate_strict() {
        let password = b"test_password";
        let hashed = hash(password).expect("Failed to hash password");

        // Should succeed with correct password
        assert!(validate_strict(password, &hashed).is_ok());

        // Should fail with incorrect password
        let wrong_password = b"wrong_password";
        assert!(validate_strict(wrong_password, &hashed).is_err());
    }
}
