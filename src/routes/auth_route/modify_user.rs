use std::collections::HashMap;

use axum::{
    Extension,
    extract::{Query, State},
    http::StatusCode,
};
use tracing::info;
use validator::Validate;

use tokio::time::{Duration, sleep};

use crate::{
    consts::auth_const::{
        AUTH_PASSWORD_TABLE, EMAIL_CHANGE_TOKEN_TABLE, EMAIL_VERIFICATION_TABLE,
        PASSWORD_RESET_TOKEN_TABLE, USER_TABLE,
    },
    errors::{Error, Result},
    middleware::UserId,
    models::{
        user::{AuthProvider, User, UserWithPassword},
        verification::{
            CreateEmailChangeToken, CreateEmailVerification, EmailChangeToken, EmailVerification,
        },
    },
    state::AppState,
    utils::{
        email_verification::{gen_hash_from_token, generate_verification_token},
        pwd::hash,
        time::time_now,
        validated_form::{ValidatedForm, ValidatedJson},
        validator::validate_password,
    },
};

// TODO: make sure deleted_at is check during authentication and authorization

#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct ResendEmailVerificationFormRequest {
    #[validate(email)]
    pub email: String,
}

pub async fn resend_email_verification(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    ValidatedJson(input): ValidatedJson<ResendEmailVerificationFormRequest>,
) -> Result<(StatusCode, String)> {
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
    Extension(UserId(user_id)): Extension<UserId>,
    ValidatedJson(input): ValidatedJson<RequestEmailChangeFormRequest>,
) -> Result<(StatusCode, String)> {
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

#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct RequestForgotPasswordFormRequest {
    #[validate(email)]
    pub email: String,
}
pub async fn request_forgot_password(
    State(state): State<AppState>,
    ValidatedJson(input): ValidatedJson<RequestForgotPasswordFormRequest>,
) -> Result<(StatusCode, String)> {
    // ? User enters email address on forgot password form
    let find_email = async move |state: AppState, email: String| -> Result<Vec<User>> {
        let start = std::time::Instant::now();
        let user: Vec<User> = state
            .sdb
            .query("SELECT * FROM type::table($table) WHERE email = $email;")
            .bind(("table", USER_TABLE))
            .bind(("email", email))
            .await?
            .take(0)?;

        let min_duration = Duration::from_millis(200);
        let elapsed = start.elapsed();
        if elapsed < min_duration {
            sleep(min_duration - elapsed).await;
        }

        Ok(user)
    };
    if let Some(user) = find_email(state.clone(), input.email.clone())
        .await?
        .first()
    {
        let user_id = user.clone().id;
        let check_token: Vec<EmailVerification> = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE email = $email AND expires_at > time::now();",
        ) // not already expired
        .bind(("table", PASSWORD_RESET_TOKEN_TABLE))
        .bind(("email", input.email.clone()))
        .await?
        .take(0)?;

        for a in check_token {
            let _: Option<EmailVerification> = state.sdb.delete(a.id.clone()).await?;
        }
        let token = generate_verification_token();
        let token_data = CreateEmailChangeToken::init(user_id, input.email, token.1);
        let _: Option<EmailVerification> = state
            .sdb
            .create(PASSWORD_RESET_TOKEN_TABLE)
            .content(token_data)
            .await?;

        info!("request password token = {}", token.0);
        ////  Send new verification email (https://rust-auth.com/password/validate-token?token=...)
        // TODO: send token to mail token = ``;
        // TODO:  Send email regardless of whether user exists (prevent email enumeration)
        // TODO:  Log password reset request event (include IP address)
    }
    return Ok((
        StatusCode::OK,
        "If email exists, reset link has been sent to your Email Address provided".to_string(),
    ));
}

#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct ForgottenPasswordFormRequest {
    #[validate(length(min = 8, max = 16), custom(function = "validate_password"))]
    pub password: String,
    #[validate(length(min = 8, max = 16), custom(function = "validate_password"))]
    pub confirm_password: String,
    pub token: Option<String>,
}

pub async fn forgotten_password_token_validation(
    State(state): State<AppState>,
    ValidatedForm(input): ValidatedForm<ForgottenPasswordFormRequest>,
) -> Result<(StatusCode, String)> {
    // ? User clicks reset link in email

    //TODO: Validate session contains valid reset token
    //TODO: Display password reset form with:
    //TODO: New password field
    //TODO: Confirm password field
    //TODO: Password strength indicator
    //TODO: Submit button
    //TODO: Include hidden token field or keep in session
    //TODO: Add CSRF protection

    if let Some(token) = input.token {
        let token = gen_hash_from_token(token.to_string());

        let check_token: Vec<EmailChangeToken> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE token = $token AND expires_at > time::now();") // not already expired
        .bind(("table", PASSWORD_RESET_TOKEN_TABLE))
        .bind(("token", token))
        .await?
        .take(0)?;

        if let Some(token) = check_token.first() {
            let token_id = token.id.clone();
            let user_id = token.user_id.clone();
            // let new_email = token.email.clone();

            let get_user: Vec<UserWithPassword> = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE user_id = $user_id AND user_id.auth_provider = $provider AND user_id.email_verified = true",
        )
        .bind(("table", AUTH_PASSWORD_TABLE))
        .bind(("user_id", user_id))
        .bind(("provider", AuthProvider::Classic))
        .await?
        .take(0)?;

            if let Some(user) = get_user.first() {
                let mut user = user.clone();
                let password_hash = hash(input.password.as_bytes())?;
                user.password_hash = password_hash;
                user.updated_at = Some(time_now());
                let _: Option<User> = state.sdb.update(user.id.clone()).content(user).await?;
                let _: Option<EmailChangeToken> = state.sdb.delete(token_id).await?;
            }
            // TODO:  Log Password change completion event
            // TODO:  Redirect to login page
        }
    }

    return Ok((
        StatusCode::OK,
        "Password updated successfully, please login again".to_string(),
    ));
}

#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct ResetPasswordFormRequest {
    #[validate(length(min = 8, max = 16), custom(function = "validate_password"))]
    pub password: String,
    #[validate(length(min = 8, max = 16), custom(function = "validate_password"))]
    pub confirm_password: String,
}

pub async fn reset_password(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    ValidatedForm(input): ValidatedForm<ResetPasswordFormRequest>,
) -> Result<(StatusCode, String)> {
    // ?  User submits new password form
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

pub async fn delete_user(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) -> Result<(StatusCode, String)> {
    let get_user: Vec<User> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE id = $id;")
        .bind(("table", USER_TABLE))
        .bind(("id", user_id))
        .await?
        .take(0)?;

    if let Some(user) = get_user.first() {
        // ! 1. soft delete
        let mut user = user.clone();
        user.deleted_at = Some(time_now());
        user.updated_at = Some(time_now());
        let _: Option<User> = state.sdb.update(user.id.clone()).content(user).await?;

        // ! 2. delete all relation to user then delete user
    }

    return Ok((StatusCode::OK, "User Deleted".to_string()));
}
