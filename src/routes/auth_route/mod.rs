use std::{sync::Arc, time::Duration};
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::{
    routes::auth_route::{
        modify_user::{
            confirm_email_change, delete_user, forgotten_password_token_validation,
            request_email_change, request_forgot_password, resend_email_verification,
            reset_password, verify_email,
        },
        user::{sign_in, sign_up},
    },
    state::AppState,
};

pub mod modify_user;
pub mod user;

pub fn auth_router(config: AppState) -> Router<AppState> {
    // ? rate limiter for resend email verification
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(3600)
            .burst_size(3)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .unwrap(),
    );
    let governor_limiter = governor_conf.limiter().clone();
    let interval = Duration::from_secs(60);
    // a separate background task to clean up
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            tracing::info!("rate limiting storage size: {}", governor_limiter.len());
            governor_limiter.retain_recent();
        }
    });
    Router::new()
        //  .route("/", get(root_route))
        .route("/signin", post(sign_in))
        .route("/signup", post(sign_up))
        .route(
            "/email/resend-verification",
            post(resend_email_verification).layer(GovernorLayer {
                config: governor_conf,
            }),
        )
        .route("/email/verify", get(verify_email))
        .route("/email/change-request", post(request_email_change))
        .route("/email/change-confirm", post(confirm_email_change))
        .route("/password/reset-request", post(request_forgot_password))
        .route(
            "/password/validate-token",
            post(forgotten_password_token_validation),
        )
        .route("/password/reset", post(reset_password))
        .route("/delete", delete(delete_user))
        .with_state(config)
}
