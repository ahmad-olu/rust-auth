use validator::ValidationError;

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    let bad_usernames = ["admin", "root", "xXxShad0wxXx"];
    let disallowed_prefixes = ["admin_", "test_", "sys_", "__"];

    if bad_usernames.contains(&username) {
        return Err(ValidationError::new("blacklisted_username"));
    }

    if disallowed_prefixes
        .iter()
        .any(|prefix| username.starts_with(prefix))
    {
        return Err(ValidationError::new("invalid_prefix"));
    }

    if username.len() < 3 {
        return Err(ValidationError::new("username_too_short"));
    }

    if username.len() > 20 {
        return Err(ValidationError::new("username_too_long"));
    }

    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() < 8 {
        return Err(ValidationError::new("password_too_short"));
    }

    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(ValidationError::new("password_needs_uppercase"));
    }

    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(ValidationError::new("password_needs_lowercase"));
    }

    if !password.chars().any(|c| c.is_numeric()) {
        return Err(ValidationError::new("password_needs_number"));
    }

    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(ValidationError::new("password_needs_special_char"));
    }

    Ok(())
}
