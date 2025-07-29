use axum::{
    Router,
    routing::{get, post},
};

use crate::{
    routes::{
        auth_route::user::{sign_in, sign_up},
        root_route,
    },
    state::AppState,
};

pub mod user;

pub fn auth_router(config: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(root_route))
        .route("/signin", post(sign_in))
        .route("/signup", post(sign_up))
        // .route("/refresh", post(refresh))
        .with_state(config)
}
