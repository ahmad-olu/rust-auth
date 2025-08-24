use std::{sync::Arc, time::Duration};
use tower_governor::{governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor};

use axum::{
    Router, middleware,
    routing::{delete, get, patch, post},
};

use crate::{
    middleware::auth_jwt_middleware,
    routes::auth_route::{
        modify_user::{
            confirm_email_change, delete_user, forgotten_password_token_validation,
            request_email_change, request_forgot_password, resend_email_verification,
            reset_password, verify_email,
        },
        organization::{
            bulk_member_import, create_organization, create_organization_memberships, data_export,
            delete_organization, delete_organization_memberships, leave_organization,
            organization_migration, organization_switch, read_organization,
            read_organization_memberships, read_organizations, update_organization,
            update_organization_memberships,
        },
        user::{sign_in, sign_up},
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

    Router::new()
        .merge(user(config.clone()))
        .nest("/organizations", organization(config.clone()))
        .with_state(config)
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

fn organization(config: AppState) -> Router<AppState> {
    Router::new()
        // ! org
        .route("/", post(create_organization))
        .route("/{org_id}", get(read_organization))
        .route("/", get(read_organizations))
        .route("/{org_id}", patch(update_organization))
        .route("/{org_id}", delete(delete_organization))
        // ! org membership
        .route(
            "/{org_id}/memberships",
            post(create_organization_memberships),
        )
        .route("/{org_id}/memberships", get(read_organization_memberships))
        .route(
            "/{org_id}/memberships/{member_id}",
            patch(update_organization_memberships),
        )
        .route(
            "/{org_id}/memberships/{member_id}",
            delete(delete_organization_memberships),
        )
        .route("/{org_id}/leave", post(leave_organization))
        // ! other actions
        .route("/{org_id}/switch", post(organization_switch))
        .route(
            "/{org_id}/memberships/bulk-import",
            post(bulk_member_import),
        )
        .route("/{org_id}/data-export", get(data_export))
        .route("/{org_id}/migrate", post(organization_migration))
        .layer(middleware::from_fn(auth_jwt_middleware))
        .with_state(config)
}

// TODO : other auth to consider: two factor, username, anonymous, phone number, magic link, email otp, passkey, generic oauth, one tap
