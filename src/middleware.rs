use axum::{
    extract::{FromRequest, Request},
    http::{header::AUTHORIZATION, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::errors::{Error, Result as RResult};
use crate::utils::jwt::decode_jwt;

#[derive(Debug, Clone)]
pub struct UserId(pub String);

pub async fn auth_jwt_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, Response> {
    let request = buffer_request_and_authenticate(request).await?;

    Ok(next.run(request).await)
}

async fn buffer_request_and_authenticate<B>(request: Request<B>) -> Result<Request<B>, Response> {
    let (mut parts, body) = request.into_parts();
    let user_id = check_auth_parts(&parts)
        .await
        .map_err(IntoResponse::into_response)?;

    parts.extensions.insert(user_id);

    Ok(Request::from_parts(parts, body))
}

async fn check_auth_parts(parts: &Parts) -> RResult<UserId> {
    let header_value = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or(Error::MissingToken)?
        .to_str()
        .map_err(|_| Error::InvalidToken)?;

    let mut parts = header_value.trim().splitn(2, ' ');

    let scheme = parts.next().ok_or(Error::MissingToken)?;
    let token = parts.next().ok_or(Error::MissingToken)?;

    if scheme != "Bearer" {
        tracing::warn!("Invalid auth scheme: {scheme}");
        return Err(Error::InvalidScheme);
    }

    decode_jwt(token).map(|data| UserId(data.claims.id))
}

impl<S> FromRequest<S> for UserId
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request(req: Request, _state: &S) -> RResult<Self> {
        req.extensions()
            .get::<UserId>()
            .cloned()
            .ok_or(Error::NotFound)
    }
}
