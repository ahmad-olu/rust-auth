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
        .query("SELECT * FROM type::table($table) WHERE email = $email AND id = $id AND deleted_at == None;")
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
        .query("SELECT * FROM type::table($table) WHERE user_id = $user_id AND expires_at > time::now() AND user_id.deleted_at == None;") // not already expired
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
        .query("SELECT * FROM type::table($table) WHERE token = $e_token AND expires_at < time::now() AND user_id.deleted_at == None;")
        .bind(("table", EMAIL_VERIFICATION_TABLE))
        .bind(("e_token", token))
        .await?
        .take(0)?;

        if let Some(token) = check_token.first() {
            let token_id = token.id.clone();
            let user_id = token.user_id.clone();

            let get_user: Vec<User> = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE id = $id AND auth_provider = $provider AND email_verified != true AND deleted_at == None;",
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
        .query("SELECT * FROM type::table($table) WHERE email = $email AND deleted_at == None;")
        .bind(("table", USER_TABLE))
        .bind(("email", input.new_email.clone()))
        .await?
        .take(0)?;

    if !check_user.is_empty() {
        return Err(Error::EmailExist(input.new_email.clone()));
    }
    let _: Vec<EmailChangeToken> = state
        .sdb
        .query("DELETE type::table($table) WHERE email = $email AND user_id.deleted_at == None;") // not already expired
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
        .query("SELECT * FROM type::table($table) WHERE token = $e_token AND expires_at < time::now() AND user_id.deleted_at == None;") // not already expired
        .bind(("table", EMAIL_CHANGE_TOKEN_TABLE))
        .bind(("e_token", token))
        .await?
        .take(0)?;

        if let Some(token) = check_token.first() {
            let token_id = token.id.clone();
            let user_id = token.user_id.clone();
            let new_email = token.email.clone();

            let get_user: Vec<User> = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE id = $id AND auth_provider = $provider AND email_verified != true AND deleted_at == None;",
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
            .query("SELECT * FROM type::table($table) WHERE email = $email AND deleted_at == None;")
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
            "SELECT * FROM type::table($table) WHERE email = $email AND expires_at > time::now() AND user_id.deleted_at == None;",
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
        .query("SELECT * FROM type::table($table) WHERE token = $p_token AND expires_at < time::now() AND user_id.deleted_at == None;") // not already expired
        .bind(("table", PASSWORD_RESET_TOKEN_TABLE))
        .bind(("p_token", token))
        .await?
        .take(0)?;

        if let Some(token) = check_token.first() {
            let token_id = token.id.clone();
            let user_id = token.user_id.clone();
            // let new_email = token.email.clone();

            let get_user: Vec<UserWithPassword> = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE user_id = $user_id AND user_id.auth_provider = $provider AND user_id.email_verified = true AND user_id.deleted_at == None;",
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

    let user_p: Vec<UserWithPassword> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE user_id = $user_id;")
        .bind(("table", AUTH_PASSWORD_TABLE))
        .bind(("user_id", user_id.clone()))
        .await?
        .take(0)?;

    if let Some(user) = user_p.first() {
        let user = user.clone();
        let hash_input_password = hash(input.password.as_bytes())?;
        if hash_input_password == user.password_hash {
            return Err(Error::Unknown);
        }

        let get_user: Vec<UserWithPassword> = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE user_id = $user_id AND user_id.auth_provider = $provider;",
        )
        .bind(("table", AUTH_PASSWORD_TABLE))
        .bind(("user_id", user_id))
        .bind(("provider", AuthProvider::Classic))
        .await?
        .take(0)?;

        if let Some(user) = get_user.first() {
            let mut user = user.clone();
            user.password_hash = hash_input_password;
            user.updated_at = Some(time_now());
            let _: Option<UserWithPassword> =
                state.sdb.update(user.id.clone()).content(user).await?;
        }
        // TODO:  Validate new password meets strength
        // TODO:    - Not in common password dictionary
        // TODO:  Hash new password using bcrypt/Argon2
        // TODO:  Log successful password reset event
        // TODO:  Send password change confirmation email
        // TODO:  Redirect to login page with success message
    }
    return Ok((
        StatusCode::OK,
        "Password reset successfully, please login again".to_string(),
    ));
}

pub async fn delete_user(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) -> Result<(StatusCode, String)> {
    let get_user: Vec<User> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE id = $id AND deleted_at != None;")
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

#[cfg(test)]
mod modify_user_tests {
    use std::sync::Mutex;

    use axum::{
        body::Body,
        http::{
            Request, StatusCode,
            header::{AUTHORIZATION, CONTENT_TYPE},
        },
    };
    use http_body_util::BodyExt;
    use once_cell::sync::Lazy;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::{
        app,
        consts::auth_const::{
            AUTH_PASSWORD_TABLE, EMAIL_CHANGE_TOKEN_TABLE, EMAIL_VERIFICATION_TABLE,
            PASSWORD_RESET_TOKEN_TABLE, USER_TABLE,
        },
        models::verification::EmailChangeToken,
        routes::auth_route::user::SignInFormResponse,
        state::AppState,
    };

    const SIGN_UP_URI: &str = "/auth/signup";
    const SIGN_IN_URI: &str = "/auth/signin";
    const DELETE_IN_URI: &str = "/auth/user";
    const RESEND_EMAIL_VERIFICATION_URI: &str = "/auth/email/resend-verification";
    const REQUEST_EMAIL_CHANGE_URI: &str = "/auth/email/change-request";

    static EMAIL_CHANGE_CONFIRM_URI: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

    const FORM_DATA_SIGNUP: &str =
        "email=alana5%40gmail.com&username=allana3&password=Allana%24n09878";
    const FORM_DATA_SIGNIN: &str = "email=alana5%40gmail.com&password=Allana%24n09878";

    static JWT_TOKEN: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

    #[tokio::test]
    async fn test_full_auth_flow() {
        clear_data().await;
        test_sign_up().await;
        test_sign_in().await;
        test_resend_email_verification().await;

        test_request_email_change().await;
        test_delete_user().await;
    }

    async fn test_sign_up() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SIGN_UP_URI)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(FORM_DATA_SIGNUP))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    async fn test_sign_in() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SIGN_IN_URI)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(FORM_DATA_SIGNIN))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: SignInFormResponse = serde_json::from_slice(&body_bytes).unwrap();
        *JWT_TOKEN.lock().unwrap() = Some(format!("Bearer {}", body.access_token));
        assert_eq!(body.token_type, "Bearer");
    }

    async fn test_resend_email_verification() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(RESEND_EMAIL_VERIFICATION_URI)
                    .header(AUTHORIZATION, JWT_TOKEN.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"email":"alana5@gmail.com"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // let body: serde_json::Value =
        //     serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
        //         .unwrap();
        // assert_eq!(body, serde_json::json!("hello"));
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn test_request_email_change() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(REQUEST_EMAIL_CHANGE_URI)
                    .header(AUTHORIZATION, JWT_TOKEN.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"new_email":"alana92@gmail.com"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let v: Vec<EmailChangeToken> = state
            .sdb
            .query("SELECT * FROM type::table($table) WHERE email = $email;")
            .bind(("table", EMAIL_CHANGE_TOKEN_TABLE))
            .bind(("email", "alana92@gmail.com"))
            .await
            .unwrap()
            .take(0)
            .unwrap();

        let verification_token = v.first().unwrap().token.clone();
        *EMAIL_CHANGE_CONFIRM_URI.lock().unwrap() = Some(format!(
            "/auth/email/change-confirm?token={}",
            verification_token
        ));
    }

    async fn test_delete_user() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(DELETE_IN_URI)
                    .header(AUTHORIZATION, JWT_TOKEN.lock().unwrap().clone().unwrap())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
    async fn clear_data() {
        #[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
        pub struct Record {
            pub id: surrealdb::RecordId,
        }
        let tables = [
            USER_TABLE,
            AUTH_PASSWORD_TABLE,
            EMAIL_VERIFICATION_TABLE,
            EMAIL_CHANGE_TOKEN_TABLE,
            PASSWORD_RESET_TOKEN_TABLE,
        ];
        let state = AppState::init().await.unwrap();
        for table in tables {
            let _: Vec<Record> = state.sdb.delete(table).await.unwrap();
        }
    }
}
