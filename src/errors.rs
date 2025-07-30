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

    #[error("unknown Error")]
    Unknown,
    #[error("Not Found")]
    NotFound,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        // let res = || (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error").into_response();
        match self {
            Error::Argon2Error(error) => {
                error!("Argon 2 Error:{:#?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error").into_response()
            }
            Error::JwTError(error) => {
                error!("JWT Error:{:#?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error").into_response()
            }
            Error::SurrealError(error) => {
                error!("Surreal  Error:{:#?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error").into_response()
            }
            Error::IoError(error) => {
                error!("Io  Error:{:#?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error").into_response()
            }
            Error::AxumError(error) => {
                error!("Axum  Error:{:#?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error").into_response()
            }
            Error::ValidationError(error) => {
                let message = format!("Input validation error: [{}]", error).replace('\n', ", ");
                error!("Validation Error:{:#?}", error);
                (StatusCode::BAD_REQUEST, message).into_response()
            }
            Error::AxumFormRejection(error) => {
                error!("Axum Form Rejection Error:{:#?}", error);
                (StatusCode::BAD_REQUEST, error.to_string()).into_response()
            }
            Error::AxumJsonRejection(error) => {
                error!("Axum Json Rejection Error:{:#?}", error);
                (StatusCode::BAD_REQUEST, error.to_string()).into_response()
            }
            Error::InvalidLoginDetails => {
                error!("Invalid login details");
                (StatusCode::BAD_REQUEST, "Invalid Login Details").into_response()
            }
            Error::EmailExist(email) => (
                StatusCode::BAD_REQUEST,
                format!("User with email {} already exists!", email),
            )
                .into_response(),
            Error::Unknown => (StatusCode::BAD_REQUEST, "Unknown").into_response(),
            Error::NotFound => (StatusCode::NOT_FOUND, "Not Found").into_response(),
        }
    }
}
