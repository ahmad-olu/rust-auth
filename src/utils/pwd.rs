use crate::{
    errors::Result,
    models::user::{DEFAULT_PASSWORD_VERSION, PasswordVersion},
};

// #[derive(Debug)]
// pub enum PwdVersionStatus {
//     Ok,
//     Outdated,
// }

pub fn hash(password: &[u8]) -> Result<String> {
    match DEFAULT_PASSWORD_VERSION {
        PasswordVersion::V1 => Ok(argon2_pwd::hash(password)?),
        //_ => Err(Error::InternalServerError),
    }
}
pub async fn validate<F, Fut>(
    version: &PasswordVersion,
    password: &[u8],
    hash: &str,
    f: F,
) -> Result<bool>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    if version == &DEFAULT_PASSWORD_VERSION {
        match DEFAULT_PASSWORD_VERSION {
            PasswordVersion::V1 => return Ok(argon2_pwd::validate(password, hash)?),
            //_ => Err(Error::InternalServerError),
        }
    }

    let valid = match version {
        PasswordVersion::V1 => argon2_pwd::validate(password, hash)?,
    };

    if valid {
        let new_hash = match DEFAULT_PASSWORD_VERSION {
            PasswordVersion::V1 => argon2_pwd::hash(password)?,
        };

        f(new_hash).await?;
    }

    Ok(valid)
}

fn validate_strict(_password: &[u8], _hash: &str) -> Result<()> {
    todo!()
}

mod argon2_pwd {
    use argon2::{
        Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
        password_hash::{SaltString, rand_core::OsRng},
    };

    use crate::{
        errors::{Error, Result},
        models::user::PasswordVersion,
    };

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
}

#[cfg(test)]
mod tests {
    use crate::{
        models::user::PasswordVersion,
        utils::pwd::{hash, validate, validate_strict},
    };

    #[tokio::test]
    async fn test_hash_and_validate() {
        let password = b"my_secure_password";

        // Hash the password
        let hashed = hash(password).expect("Failed to hash password");
        println!("Hashed password: {}", hashed);

        // Validate with correct password
        assert!(
            validate(&PasswordVersion::V1, password, &hashed, |_| async move {
                Ok(())
            })
            .await
            .expect("Validation failed")
        );

        // Validate with incorrect password
        let wrong_password = b"wrong_password";
        assert!(
            validate(
                &PasswordVersion::V1,
                wrong_password,
                &hashed,
                |_| async move { Ok(()) }
            )
            .await
            .expect("Validation failed")
        );
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
