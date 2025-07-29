use argon2::password_hash::Error as ArError;
use axum::{http::StatusCode, response::IntoResponse};
use jsonwebtoken::errors::Error as JWError;
use surrealdb::Error as SError;

use thiserror::Error;

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
        let res = (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error").into_response();
        match self {
            Error::Argon2Error(_error) => res,
            Error::JwTError(_error) => res,
            Error::SurrealError(_error) => res,
            Error::IoError(_error) => res,
            Error::AxumError(_error) => res,
            Error::InvalidLoginDetails => {
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
