use argon2::password_hash::Error as ArError;
use axum::{http::StatusCode, response::IntoResponse};
use jsonwebtoken::errors::Error as JWError;
use surrealdb::Error as SError;

use thiserror::Error;
use tracing::error;

use crate::models::permission::Permission;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Internal Server Error")]
    InternalServerError,

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

    // ! org
    #[error("Org name taken")]
    OrgNameTaken,
    #[error("Org creation limit")]
    OrgCreationLimitReached,

    #[error("Access denied: missing permission {0:?}")]
    AccessDenied(Permission),

    #[error("User not found in organization")]
    UserNotInOrganization,

    #[error("User not found in team")]
    UserNotInTeam,

    #[error("Organization not found")]
    OrganizationNotFound,

    #[error("Team not found")]
    TeamNotFound,

    #[error("Role not found")]
    RoleNotFound,

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    // #[error("Database error: {0}")]
    // DatabaseError(String),
    #[error("Custom: {0}")]
    Custom(String),
    #[error("Team name taken")]
    TeamNameTaken,
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
                //  print!("=======> Surreal  Error:{:#?}", error);
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
            Error::OrgNameTaken => (
                StatusCode::CONFLICT,
                "Organization name UnAvailable, try another.".to_string(),
            ),
            Error::OrgCreationLimitReached => (
                StatusCode::UNAUTHORIZED,
                "You have reached you Organization creation limit... Pele".to_string(),
            ),
            Error::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Error".to_string(),
            ),
            Error::AccessDenied(permission) => (
                StatusCode::UNAUTHORIZED,
                format!("Access denied: missing permission {0:?}", permission),
            ),
            Error::UserNotInOrganization => (
                StatusCode::UNAUTHORIZED,
                format!("User not found in organization"),
            ),
            Error::UserNotInTeam => (StatusCode::UNAUTHORIZED, format!("User not found in team")),
            Error::OrganizationNotFound => {
                (StatusCode::UNAUTHORIZED, format!("Organization not found"))
            }
            Error::TeamNotFound => (StatusCode::UNAUTHORIZED, format!("Team not found")),
            Error::RoleNotFound => (StatusCode::UNAUTHORIZED, format!("Role not found")),
            Error::InvalidOperation(op) => (
                StatusCode::UNAUTHORIZED,
                format!("Invalid operation: {0}", op),
            ),
            Error::Custom(val) => {
                //  println!("custom ==> {}", val);
                (StatusCode::BAD_REQUEST, format!("{0}", val))
            }
            Error::TeamNameTaken => (
                StatusCode::CONFLICT,
                "Team name UnAvailable, try another.".to_string(),
            ),
        };
        (status, message).into_response()
    }
}
