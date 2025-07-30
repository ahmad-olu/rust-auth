use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use surrealdb::RecordId;
use tracing::info;
use validator::Validate;

use crate::{
    consts::auth_const::{EMAIL_CHANGE_TOKEN_TABLE, EMAIL_VERIFICATION_TABLE, USER_TABLE},
    errors::{Error, Result},
    models::{
        user::{AuthProvider, User},
        verification::{
            CreateEmailChangeToken, CreateEmailVerification, EmailChangeToken, EmailVerification,
        },
    },
    state::AppState,
    utils::{
        email_verification::{gen_hash_from_token, generate_verification_token},
        time::time_now,
        validated_form::ValidatedJson,
    },
};

#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct ResendEmailVerificationFormRequest {
    #[validate(email)]
    pub email: String,
}

pub async fn resend_email_verification(
    State(state): State<AppState>,
    ValidatedJson(input): ValidatedJson<ResendEmailVerificationFormRequest>,
    //get user id from jwt
) -> Result<(StatusCode, String)> {
    // TODO:  Authenticate current session
    let user_id = RecordId::from_table_key("user", "aaaaaaaaa"); // placeholder
    let get_user: Vec<User> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE email = $email AND id = $user_id;")
        .bind(("table", USER_TABLE))
        .bind(("email", input.email.clone()))
        .bind(("id", user_id))
        .await?
        .take(0)?;

    if get_user.is_empty() {
        return Err(Error::EmailNotExist(input.email.clone()));
    }

    let user_id = get_user.first().unwrap().id.clone();
    let check_token: Vec<EmailVerification> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE user_id = $user_id AND expires_at > time::now();") // not already expired
        .bind(("table", EMAIL_VERIFICATION_TABLE))
        .bind(("user_id", user_id.clone()))
        .await?
        .take(0)?;

    for a in check_token {
        // let _:Vec<EmailVerification> = state.sdb.query("UPDATE type::table($table) SET expires_at = time::now() - 1s WHERE user_id = $user_id AND expires_at > time::now();")
        // .bind(("table", EMAIL_VERIFICATION_TABLE))
        // .bind(("user_id", a.id.clone())).await?
        // .take(0)?;
        let _: Option<EmailVerification> = state.sdb.delete(a.id.clone()).await?;
    }

    let token = generate_verification_token();
    let token_data = CreateEmailVerification::init(user_id, token.1);
    let _: Option<EmailVerification> = state
        .sdb
        .create(EMAIL_VERIFICATION_TABLE)
        .content(token_data)
        .await?;

    info!("verification token = {}", token.0);
    // TODO: Send new verification email (https://rust-auth.com/email/verify?token=...)
    // TODO: Log verification email resend event
    return Ok((
        StatusCode::OK,
        "New verification email sent. Check your Email Address provided".to_string(),
    ));
}

pub async fn verify_email(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<(StatusCode, String)> {
    // ? User clicks verification link in email
    let q_token = params.get("token");
    if let Some(q_token) = q_token {
        let token = gen_hash_from_token(q_token.to_string());

        let check_token: Vec<EmailVerification> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE token = $token AND expires_at > time::now();") // not already expired
        .bind(("table", EMAIL_VERIFICATION_TABLE))
        .bind(("token", token))
        .await?
        .take(0)?;

        if let Some(token) = check_token.first() {
            let token_id = token.id.clone();
            let user_id = token.user_id.clone();

            let get_user: Vec<User> = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE id = $id AND auth_provider = $provider AND email_verified != true",
        )
        .bind(("table", USER_TABLE))
        .bind(("id", user_id))
        .bind(("provider", AuthProvider::Classic))
        .await?
        .take(0)?;

            if let Some(user) = get_user.first() {
                let mut user = user.clone();
                user.email_verified = Some(true);
                user.updated_at = Some(time_now());
                let _: Option<User> = state.sdb.update(user.id.clone()).content(user).await?;
                let _: Option<EmailVerification> = state.sdb.delete(token_id).await?;
            }
            // TODO:  Log successful email verification event
            // TODO:  Redirect user to success page or auto-login
        }
    } else {
        return Err(Error::NotFound);
    }
    return Ok((StatusCode::OK, "Email verified successfully".to_string()));
}

#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct RequestEmailChangeFormRequest {
    #[validate(email)]
    pub new_email: String,
}

pub async fn request_email_change(
    State(state): State<AppState>,
    ValidatedJson(input): ValidatedJson<RequestEmailChangeFormRequest>,
    //get user id from jwt
) -> Result<(StatusCode, String)> {
    // TODO:  Authenticate current session
    let user_id = RecordId::from_table_key("user", "aaaaaaaaa"); // placeholder
    // ? TODO:      User submits new email address

    let check_user: Vec<User> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE email = $email;")
        .bind(("table", USER_TABLE))
        .bind(("email", input.new_email.clone()))
        .await?
        .take(0)?;

    if !check_user.is_empty() {
        return Err(Error::EmailExist(input.new_email.clone()));
    }
    let _: Vec<EmailChangeToken> = state
        .sdb
        .query("DELETE type::table($table) WHERE email = $email;") // not already expired
        .bind(("table", EMAIL_CHANGE_TOKEN_TABLE))
        .bind(("email", input.new_email.clone()))
        .await?
        .take(0)?;

    let email_change_token = generate_verification_token();
    let create_email_change_data =
        CreateEmailChangeToken::init(user_id, input.new_email, email_change_token.1);
    let _: Option<EmailChangeToken> = state
        .sdb
        .create(EMAIL_CHANGE_TOKEN_TABLE)
        .content(create_email_change_data)
        .await?;
    info!("verification token = {}", email_change_token.0);
    // TODO:  Send verification email to NEW email address
    // TODO:  Log email change request event
    return Ok((
        StatusCode::OK,
        "Verification sent to new email address. Check your Email Address provided".to_string(),
    ));
}

pub async fn confirm_email_change(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<(StatusCode, String)> {
    // ? User clicks verification link for email change
    if let Some(token) = params.get("token") {
        let token = gen_hash_from_token(token.to_string());

        let check_token: Vec<EmailChangeToken> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE token = $token AND expires_at > time::now();") // not already expired
        .bind(("table", EMAIL_CHANGE_TOKEN_TABLE))
        .bind(("token", token))
        .await?
        .take(0)?;

        if let Some(token) = check_token.first() {
            let token_id = token.id.clone();
            let user_id = token.user_id.clone();
            let new_email = token.email.clone();

            let get_user: Vec<User> = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE id = $id AND auth_provider = $provider AND email_verified != true",
        )
        .bind(("table", USER_TABLE))
        .bind(("id", user_id))
        .bind(("provider", AuthProvider::Classic))
        .await?
        .take(0)?;

            if let Some(user) = get_user.first() {
                let mut user = user.clone();
                user.email = new_email;
                user.email_verified = Some(true);
                user.updated_at = Some(time_now());
                let _: Option<User> = state.sdb.update(user.id.clone()).content(user).await?;
                let _: Option<EmailChangeToken> = state.sdb.delete(token_id).await?;
            }
            // TODO:  Log email change completion event
            // TODO:  Redirect to login page
        }
    }

    return Ok((
        StatusCode::OK,
        "Email updated successfully, please login again".to_string(),
    ));
}

pub async fn request_forgot_password(
    State(state): State<AppState>,
) -> Result<(StatusCode, String)> {
    //TODO:      User enters email address on forgot password form
    //TODO:  Validate email format
    //TODO:  Check rate limiting (max 5 attempts per hour per IP)
    //TODO:  Hash email to prevent timing attacks during lookup
    //TODO:  Query database for user with matching email
    //TODO:  Generate cryptographically secure reset token (32+ random bytes)
    //TODO:  Set token expiration (typically 1-2 hours from now)
    //TODO:  Store token hash with user ID and expiration in password_reset_tokens table
    //TODO:  Compose password reset email with reset link containing token
    //TODO:  Send email regardless of whether user exists (prevent email enumeration)
    //TODO:  Log password reset request event (include IP address)
    //TODO:  Return generic success response
    //TODO:  Display message: "If email exists, reset link has been sent"
    todo!()
}

pub async fn forgotten_password_token_validation(
    State(state): State<AppState>,
) -> Result<(StatusCode, String)> {
    //TODO:      User clicks reset link in email
    //TODO:  Extract token from URL parameter
    //TODO:  Validate token format (length, characters)
    //TODO:  Hash received token for database lookup
    //TODO:  Query password_reset_tokens table for matching hash
    //TODO:  Check if token exists and is valid
    //TODO:  Check if token hasn't expired
    //TODO:  Check if token hasn't already been used
    //TODO:  Verify associated user account exists and is active
    //TODO:  Store token temporarily in session/memory for next step
    //TODO:  Redirect to password reset form
    //TODO:  Display password reset form with token validation success

    // ! Reset Form Display Flow

    //TODO: Validate session contains valid reset token
    //TODO: Display password reset form with:
    //TODO: New password field
    //TODO: Confirm password field
    //TODO: Password strength indicator
    //TODO: Submit button
    //TODO: Include hidden token field or keep in session
    //TODO: Add CSRF protection
    todo!()
}

pub async fn reset_password(State(state): State<AppState>) -> Result<(StatusCode, String)> {
    //TODO:      User submits new password form
    //TODO:  Extract reset token from form/session
    //TODO:  Validate token is still valid and unused
    //TODO:  Validate new password meets strength
    //TODO:    - Minimum length (8+ characters)
    //TODO:    - Contains uppercase, lowercase, numbers
    //TODO:    - Not in common password dictionary
    //TODO:    - Not same as current password
    //TODO:  Confirm password matches confirmation field
    //TODO:  Hash new password using bcrypt/Argon2
    //TODO:  Begin database transaction
    //TODO:  Update user password_hash field
    //TODO:  Mark reset token as used (set used_at timestamp)
    //TODO:  Update user's updated_at timestamp
    //TODO:  Invalidate all existing user sessions (security measure)
    //TODO:  Commit transaction
    //TODO:  Log successful password reset event
    //TODO:  Send password change confirmation email
    //TODO:  Redirect to login page with success message
    //TODO:  Display message: "Password reset successfully, please login"
    todo!()
}

pub async fn delete_user(State(state): State<AppState>) -> Result<(StatusCode, String)> {
    // * soft delete to maintain integrity with related memberships, change status to inactive
    todo!()
}
