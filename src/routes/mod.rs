use axum::Extension;

use crate::middleware::UserId;

pub mod admin_panel;
pub mod auth_route;

// pub async fn root_route() -> &'static str {
// pub async fn root_route(UserId(id): UserId) -> String {
pub async fn root_route(Extension(UserId(id)): Extension<UserId>) -> String {
    format!("id:-> {}", id)
}
