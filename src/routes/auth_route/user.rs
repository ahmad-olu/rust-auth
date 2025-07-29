use axum::{
    Json,
    extract::{Form, State},
    http::StatusCode,
};
use chrono::{DateTime, Duration, FixedOffset, Local, Utc};
use surrealdb::RecordId;

use crate::{
    consts::auth_const::{AUTH_PASSWORD_TABLE, USER_TABLE},
    errors::{Error, Result},
    models::user::{AuthProvider, User, UserReqForSignUp, UserReqWithPassword, UserWithPassword},
    state::AppState,
    utils::{
        jwt::{Claims, encode_jwt},
        pwd::{hash, validate},
    },
};

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SignUpFormRequest {
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SignUpFormResponse {
    msg: String,
}

pub async fn sign_up(
    State(state): State<AppState>,
    Form(input): Form<SignUpFormRequest>,
) -> Result<(StatusCode, Json<SignUpFormResponse>)> {
    // TODO: validate password, email and username
    let check_user: Vec<User> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE email = $email;")
        .bind(("table", USER_TABLE))
        .bind(("email", input.email.clone()))
        .await?
        .take(0)?;

    if !check_user.is_empty() {
        return Err(Error::EmailExist(input.email.clone()));
    }
    let password_hash = hash(input.password.as_bytes())?;
    let created_at = Local::now();
    let created_at: DateTime<FixedOffset> = created_at.with_timezone(&created_at.offset());
    let created_at = created_at.to_rfc3339();

    let user_data = UserReqForSignUp {
        username: input.username,
        email: input.email.clone(),
        auth_provider: AuthProvider::Classic,
        created_at,
        email_verified: false,
    };
    let create_user: Option<User> = state.sdb.create(USER_TABLE).content(user_data).await?;
    if let Some(user) = create_user {
        let auth_password = UserReqWithPassword {
            user_id: user.id,
            password_hash,
        };
        let _: Option<User> = state
            .sdb
            .create(AUTH_PASSWORD_TABLE)
            .content(auth_password)
            .await?;

        //TODO:  Generate cryptographically secure verification token (32+ random bytes)
        //TODO:  Set token expiration (typically 24-48 hours from now)
        //TODO:  Store token hash in database (either in users table or separate email_verification_tokens table)
        //TODO:  Compose verification email with verification link containing token
        //TODO:  Send email via email service provider
        //TODO:  Log verification email sent event in audit logs
        //TODO:  Return success response to user (don't reveal if email exists)
        //TODO:  Display message: "Check your email for verification link"

        return Ok((
            StatusCode::CREATED,
            Json(SignUpFormResponse {
                msg: format!("user with email: {} created", input.email),
            }),
        ));
    } else {
        return Err(Error::Unknown);
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SignInFormRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SignInFormResponse {
    pub access_token: String,
    refresh_token: String,
    pub token_type: String,
}

pub async fn sign_in(
    State(state): State<AppState>,
    Form(input): Form<SignInFormRequest>,
) -> Result<(StatusCode, Json<SignInFormResponse>)> {
    // TODO: validate email
    let get_user: Vec<UserWithPassword> = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE user_id.email = $email AND user_id.auth_provider = $provider",
        )
        .bind(("table", AUTH_PASSWORD_TABLE))
        .bind(("email", input.email))
        .bind(("provider", AuthProvider::Classic))
        .await?
        .take(0)?;

    if get_user.is_empty() {
        return Err(Error::InvalidLoginDetails);
    }
    let get_user = get_user.get(0);
    if let Some(user) = get_user {
        let password_hash = &user.password_hash;
        let validate = validate(input.password.clone().as_bytes(), password_hash)?;
        let user_id = user.user_id.to_string();
        match validate {
            true => {
                let exp = (Utc::now() + Duration::minutes(3)).timestamp() as usize; // ? TODO: Change this to days instead of minutes
                let iat = Utc::now().timestamp() as usize;
                let claims = Claims {
                    id: user_id,
                    exp,
                    iat,
                    iss: "Mangoe".to_string(),
                };
                let access_token = encode_jwt(&claims)?;
                let refresh_token = "no refresh yet".to_string(); // ?TODO: add refresh token later

                return Ok((
                    StatusCode::OK,
                    Json(SignInFormResponse {
                        access_token,
                        refresh_token,
                        token_type: "Bearer".to_string(),
                    }),
                ));
            }
            false => {
                return Err(Error::InvalidLoginDetails);
            }
        };
    }
    Err(Error::InvalidLoginDetails)
}
