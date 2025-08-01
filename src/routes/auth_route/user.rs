use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Duration, FixedOffset, Local, Utc};
use validator::Validate;

use crate::{
    consts::auth_const::{AUTH_PASSWORD_TABLE, USER_TABLE},
    errors::{Error, Result},
    models::user::{
        AuthProvider, User, UserReqForSignUp, UserReqWithPassword, UserStatus, UserWithPassword,
    },
    state::AppState,
    utils::{
        jwt::{Claims, encode_jwt},
        pwd::{hash, validate},
        time::time_now,
        validated_form::ValidatedForm,
        validator::{validate_password, validate_username},
    },
};

#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct SignUpFormRequest {
    #[validate(email)]
    pub email: String,
    #[validate(custom(function = "validate_username"))]
    pub username: String,
    #[validate(length(min = 8, max = 16), custom(function = "validate_password"))]
    pub password: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignUpFormResponse {
    pub msg: String,
}

pub async fn sign_up(
    State(state): State<AppState>,
    // Form(input): Form<SignUpFormRequest>,
    ValidatedForm(input): ValidatedForm<SignUpFormRequest>,
) -> Result<(StatusCode, Json<SignUpFormResponse>)> {
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

    let user_data = UserReqForSignUp {
        username: input.username,
        email: input.email.clone(),
        auth_provider: AuthProvider::Classic,
        created_at: time_now(),
        email_verified: false,
        status: UserStatus::Active,
    };
    let create_user: Option<User> = state.sdb.create(USER_TABLE).content(user_data).await?;
    if let Some(user) = create_user {
        let auth_password = UserReqWithPassword {
            user_id: user.id,
            password_hash,
            created_at: time_now(),
            updated_at: None,
        };
        let _: Option<UserWithPassword> = state
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

#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct SignInFormRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 16), custom(function = "validate_password"))]
    pub password: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignInFormResponse {
    pub access_token: String,
    refresh_token: String,
    pub token_type: String,
}

pub async fn sign_in(
    State(state): State<AppState>,
    ValidatedForm(input): ValidatedForm<SignInFormRequest>,
) -> Result<(StatusCode, Json<SignInFormResponse>)> {
    let get_user: Vec<UserWithPassword> = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE user_id.email = $email AND user_id.auth_provider = $provider AND user_id.deleted_at == None;",
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

#[cfg(test)]
mod user_tests {
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
    use tower::ServiceExt; // for `collect`

    use crate::{
        app,
        consts::auth_const::{AUTH_PASSWORD_TABLE, USER_TABLE},
        routes::auth_route::user::{SignInFormResponse, SignUpFormResponse},
        state::AppState,
    };

    const SIGN_UP_URI: &str = "/auth/signup";
    const SIGN_IN_URI: &str = "/auth/signin";
    const DELETE_IN_URI: &str = "/auth/user";

    // static mut TOKEN: Option<String> = None;
    static TOKEN: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

    // #[tokio::test]
    async fn test_full_auth_flow() {
        clear_data().await;
        test_sign_up().await;
        test_sign_in().await;
        test_delete_user().await;
        test_form_body_validation().await;
    }

    #[tokio::test]
    async fn test_full_possible_error_auth_flow() {
        clear_data().await;
        // test_form_body_validation().await;
    }

    async fn test_form_body_validation() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        let form_data = [
            "email=maloree&username=allana3&password=Allana%24n09878",
            "email=maloree%40gmail.com&username=__allana3&password=Allana%24n09878",
            "email=maloree%40gmail.com&username=admin&password=Allana%24n09878",
            "email=maloree%40gmail.com&username=root&password=Allana%24n09878",
            "email=maloree%40gmail.com&username=al&password=Allana%24n09878",
            "email=maloree%40gmail.com&username=allana3&password=Allana%24",
            "email=maloree%40gmail.com&username=allana3&password=Allanan09878",
            "email=maloree%40gmail.com&username=allana3&password=Alla",
        ];
        for f in form_data {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(SIGN_UP_URI)
                        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                        //  .body(Body::from(serde_json::to_vec(&json!({"":""})).unwrap()))
                        .body(Body::from(f))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        // ? sign up
        let form_data = "email=maloree%40gmail.com&username=allana3&password=Allana%24n09878";
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SIGN_UP_URI)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    //  .body(Body::from(serde_json::to_vec(&json!({"":""})).unwrap()))
                    .body(Body::from(form_data))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        // ? delete but fail
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(DELETE_IN_URI)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // ? delete but fail 2
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(DELETE_IN_URI)
                    .header(AUTHORIZATION, format!("Bearer 124543"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
    async fn test_sign_up() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        // sign up
        // let form_data =
        //     "email=maloree@email.com&username=myverysexyUsername&password=myVerySecuredPassword$22";
        let form_data = "email=alana3%40gmail.com&username=allana3&password=Allana%24n09878";
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SIGN_UP_URI)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    //  .body(Body::from(serde_json::to_vec(&json!({"":""})).unwrap()))
                    .body(Body::from(form_data))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        // user with email: {} created
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: SignUpFormResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body.msg.trim(), "user with email: alana3@gmail.com created");
    }

    async fn test_sign_in() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        let form_data = "email=alana3%40gmail.com&password=Allana%24n09878";
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SIGN_IN_URI)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    //  .body(Body::from(serde_json::to_vec(&json!({"":""})).unwrap()))
                    .body(Body::from(form_data))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: SignInFormResponse = serde_json::from_slice(&body_bytes).unwrap();
        *TOKEN.lock().unwrap() = Some(format!("Bearer {}", body.access_token));
        assert_eq!(body.token_type, "Bearer");
    }

    async fn test_delete_user() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(DELETE_IN_URI)
                    .header(AUTHORIZATION, TOKEN.lock().unwrap().clone().unwrap())
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
        let state = AppState::init().await.unwrap();
        let _: Vec<Record> = state.sdb.delete(USER_TABLE).await.unwrap();
        let _: Vec<Record> = state.sdb.delete(AUTH_PASSWORD_TABLE).await.unwrap();
    }
}
