use axum::{extract::State, http::StatusCode};
use chrono::{DateTime, Duration, FixedOffset, Local, Utc};
use tracing::info;
use validator::Validate;

use crate::{
    consts::auth_const::{EMAIL_VERIFICATION_TABLE, USER_TABLE},
    errors::{Error, Result},
    models::{
        user::{AuthProvider, User},
        verification::{CreateEmailVerification, EmailVerification},
    },
    state::AppState,
    utils::{email_verification::generate_verification_token, validated_form::ValidatedJson},
};

#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct ResendEmailVerificationFormRequest {
    #[validate(email)]
    pub email: String,
}

pub async fn resend_email_verification(
    State(state): State<AppState>,
    ValidatedJson(input): ValidatedJson<ResendEmailVerificationFormRequest>,
) -> Result<(StatusCode, String)> {
    //TODO:     User requests new verification email
    let get_user: Vec<User> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE email = $email;")
        .bind(("table", USER_TABLE))
        .bind(("email", input.email.clone()))
        .bind(("email_verified", false))
        .bind(("provider", AuthProvider::Classic))
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
        let _:Vec<EmailVerification> = state.sdb.query("UPDATE type::table($table) SET expires_at = time::now() - 1s WHERE user_id = $user_id AND expires_at > time::now();")
        .bind(("table", EMAIL_VERIFICATION_TABLE))
        .bind(("user_id", a.id.clone())).await?
        .take(0)?;
        // let _: Option<EmailVerification> = state.sdb.delete(a.id.clone()).await?;
    }

    let token_data = CreateEmailVerification::init(user_id);
    let create_token: Option<EmailVerification> = state
        .sdb
        .create(EMAIL_VERIFICATION_TABLE)
        .content(token_data)
        .await?;

    info!("verification token = {}", create_token.unwrap().token);
    // TODO: Send new verification email (https://rust-auth.com/verify_email?token=...)
    // TODO: Log verification email resend event
    return Ok((
        StatusCode::OK,
        "New verification email sent. Check your Email Address provided".to_string(),
    ));
}

pub async fn verify_email(State(state): State<AppState>) -> Result<(StatusCode, String)> {
    //TODO:      User clicks verification link in email
    //TODO:  Extract token from URL parameter
    //TODO:  Validate token format and length
    //TODO:  Hash received token to match against stored hash
    //TODO:  Query database for matching token hash
    //TODO:  Check if token exists and hasn't expired
    //TODO:  Check if token hasn't already been used
    //TODO:  Validate associated user account still exists and isn't already verified
    //TODO:  Update user record: set email_verified = true
    //TODO:  Mark verification token as used or delete it
    //TODO:  Update updated_at timestamp
    //TODO:  Log successful email verification event
    //TODO:  Redirect user to success page or auto-login
    //TODO:  Display success message: "Email verified successfully"
    todo!()
}

pub async fn request_email_change(State(state): State<AppState>) -> Result<(StatusCode, String)> {
    //TODO:      User submits new email address
    //TODO:  Authenticate current session
    //TODO:  Validate new email format and uniqueness
    //TODO:  Check current password for security
    //TODO:  Generate email change token
    //TODO:  Store pending email change with token (temp table or user field)
    //TODO:  Send verification email to NEW email address
    //TODO:  Log email change request event
    //TODO:  Return success response
    //TODO:  Display message: "Verification sent to new email address"
    todo!()
}

pub async fn confirm_email_change(State(state): State<AppState>) -> Result<(StatusCode, String)> {
    //TODO:      User clicks verification link for email change
    //TODO:  Extract and validate token
    //TODO:  Check token expiration and usage status
    //TODO:  Retrieve pending email change details
    //TODO:  Update user email to new address
    //TODO:  Set email_verified = true
    //TODO:  Clear pending email change data
    //TODO:  Invalidate all existing sessions (security measure)
    //TODO:  Log email change completion event
    //TODO:  Redirect to login page
    //TODO:  Display message: "Email updated successfully, please login again"
    todo!()
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
