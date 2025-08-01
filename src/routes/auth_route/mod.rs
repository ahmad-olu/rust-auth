use std::{sync::Arc, time::Duration};
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};

use axum::{
    Router, middleware,
    routing::{delete, get, post},
};

use crate::{
    middleware::auth_jwt_middleware,
    routes::{
        auth_route::{
            modify_user::{
                confirm_email_change, delete_user, forgotten_password_token_validation,
                request_email_change, request_forgot_password, resend_email_verification,
                reset_password, verify_email,
            },
            user::{sign_in, sign_up},
        },
        root_route,
    },
    state::AppState,
};

pub mod invitation;
pub mod modify_user;
pub mod organization;
pub mod role;
pub mod teams;
pub mod user;

pub fn auth_router(config: AppState) -> Router<AppState> {
    // ? rate limiter for resend email verification

    Router::new().merge(user(config.clone())).with_state(config)
}

fn user(config: AppState) -> Router<AppState> {
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
    let unprotected = |config: AppState| -> Router<AppState> {
        Router::new()
            .route("/signin", post(sign_in))
            .route("/signup", post(sign_up))
            .route("/email/verify", get(verify_email))
            .route("/email/change-confirm", get(confirm_email_change))
            .route("/password/reset-request", post(request_forgot_password))
            .route(
                "/password/validate-token",
                post(forgotten_password_token_validation),
            )
            .with_state(config)
    };
    let protected = |config: AppState| -> Router<AppState> {
        Router::new()
            // .route("/test", get(root_route))
            .route(
                "/email/resend-verification",
                post(resend_email_verification), // ! FIXME: Rate limiter causing error
                                                 // .layer(GovernorLayer {
                                                 //     config: governor_conf,
                                                 // }),
            )
            .route(
                "/email/change-request",
                post(request_email_change), // ! FIXME: Rate limiter causing error
                                            // .layer(GovernorLayer {
                                            //     config: governor_conf,
                                            // }),
            )
            .route("/password/reset", post(reset_password))
            .route("/user", delete(delete_user))
            .layer(middleware::from_fn(auth_jwt_middleware))
            .with_state(config)
    };
    Router::new()
        .merge(unprotected(config.clone()))
        .merge(protected(config.clone()))
        .with_state(config)
}

// TODO : other auth to consider: two factor, username, anonymous, phone number, magic link, email otp, passkey, generic oauth, one tap
