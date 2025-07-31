use argon2::password_hash::Error as ArError;
use axum::{http::StatusCode, response::IntoResponse};
use jsonwebtoken::errors::Error as JWError;
use surrealdb::Error as SError;

use thiserror::Error;
use tracing::error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Argon 2 Error: {0}")]
    Argon2Error(#[from] ArError),

    #[error("Jason web token Error: {0}")]
    JwTError(#[from] JWError),

    #[error("SurrealDb Error: {0}")]
    SurrealError(#[from] SError),

    #[error("Io Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Axum Error: {0}")]
    AxumError(#[from] axum::Error),

    #[error("Validator Error: {0}")]
    ValidationError(#[from] validator::ValidationErrors),

    #[error("Form Rejection Error: {0}")]
    AxumFormRejection(#[from] axum::extract::rejection::FormRejection),

    #[error("Form Rejection Error: {0}")]
    AxumJsonRejection(#[from] axum::extract::rejection::JsonRejection),

    #[error("Invalid login detail")]
    InvalidLoginDetails,

    #[error("User with email `{0}` already exists!")]
    EmailExist(String),

    #[error("User with email `{0}` does not exists!")]
    EmailNotExist(String),

    #[error("unknown Error")]
    Unknown,
    #[error("Not Found")]
    NotFound,

    // ! Auth
    #[error("Missing authorization token")]
    MissingToken,
    #[error("Invalid authorization token")]
    InvalidToken,
    #[error("Invalid authorization scheme")]
    InvalidScheme,
    #[error("Token expired")]
    TokenExpired,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        // let res = || (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error").into_response();
        let (status, message) = match self {
            Error::Argon2Error(error) => {
                error!("Argon 2 Error:{:#?}", error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Error".to_string(),
                )
            }
            Error::JwTError(error) => {
                error!("JWT Error:{:#?}", error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Error".to_string(),
                )
            }
            Error::SurrealError(error) => {
                error!("Surreal  Error:{:#?}", error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Error".to_string(),
                )
            }
            Error::IoError(error) => {
                error!("Io  Error:{:#?}", error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Error".to_string(),
                )
            }
            Error::AxumError(error) => {
                error!("Axum  Error:{:#?}", error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Error".to_string(),
                )
            }
            Error::ValidationError(error) => {
                let message = format!("Input validation error: [{}]", error).replace('\n', ", ");
                error!("Validation Error:{:#?}", error);
                (StatusCode::BAD_REQUEST, message)
            }
            Error::AxumFormRejection(error) => {
                error!("Axum Form Rejection Error:{:#?}", error);
                (StatusCode::BAD_REQUEST, error.to_string())
            }
            Error::AxumJsonRejection(error) => {
                error!("Axum Json Rejection Error:{:#?}", error);
                (StatusCode::BAD_REQUEST, error.to_string())
            }
            Error::InvalidLoginDetails => {
                error!("Invalid login details");
                (StatusCode::BAD_REQUEST, "Invalid Login Details".to_string())
            }
            Error::EmailExist(email) => (
                StatusCode::BAD_REQUEST,
                format!("User with email {} already exists!", email),
            ),
            Error::EmailNotExist(email) => (
                StatusCode::BAD_REQUEST,
                format!("User with email {} does not exists or verified!", email),
            ),
            Error::Unknown => (StatusCode::BAD_REQUEST, "Unknown".to_string()),
            Error::NotFound => (StatusCode::NOT_FOUND, "Not Found".to_string()),
            Error::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "Missing authorization token".to_string(),
            ),
            Error::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "Invalid authorization token".to_string(),
            ),
            Error::InvalidScheme => (
                StatusCode::UNAUTHORIZED,
                "Invalid authorization scheme".to_string(),
            ),
            Error::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired".to_string()),
        };
        (status, message).into_response()
    }
}
