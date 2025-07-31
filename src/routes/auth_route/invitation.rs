use axum::{Extension, extract::State};

use crate::{middleware::UserId, state::AppState};

pub async fn send_invitation(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {

    // * Admin creates an invite with role, email, optional message.

    // Invite created with a token.
    // Email sent to user.
    // User accepts → creates membership in organization_memberships.

    // TODO:     Authenticate user
    // TODO: Check user has members.invite permission
    // TODO: Validate email format
    // TODO: Check if user already exists in organization
    // TODO: Check for pending invitation to same email
    // TODO: Generate unique invitation token
    // TODO: Set expiration date
    // TODO: Create invitation record
    // TODO: Send invitation email with token
    // TODO: Log invitation creation event
    // TODO: Return invitation data
}

pub async fn accept_invitation(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {

    // TODO:     Validate invitation token
    // TODO: Check invitation is pending and not expired
    // TODO: Check if user account exists (create if needed)
    // TODO: Create organization membership
    // TODO: Update invitation status to accepted
    // TODO: Set accepted_at and accepted_by
    // TODO: Send welcome notification
    // TODO: Log invitation acceptance event
    // TODO: Return membership data
}

pub async fn decline_invitation(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // TODO:     Validate invitation token
    // TODO: Update invitation status to declined
    // TODO: Log invitation decline event
    // TODO: Return success confirmation
}

pub async fn resend_invitation(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // TODO:     Authenticate user
    // TODO: Check user has invitations.create permission
    // TODO: Validate invitation exists and is pending
    // TODO: Check invitation hasn't been resent too recently
    // TODO: Generate new token and expiration
    // TODO: Update invitation record
    // TODO: Send new invitation email
    // TODO: Log invitation resend event
    // TODO: Return success confirmation
}

pub async fn read_invitation(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * Admin lists pending/accepted invites.
}

// pub async fn update_invitation(State(state): State<AppState>,
//    Extension(UserId(user_id)): Extension<UserId>,) {
//     // * Status changes, e.g.,  Mark as accepted/declined/expired.
// }

pub async fn cancel_invitation(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * Cancel invitation or auto-expire using expires_at.

    // TODO:     Authenticate user
    // TODO: Check user has invitations.delete permission
    // TODO: Update invitation status to cancelled
    // TODO: Log invitation cancellation event
    // TODO: Return success confirmation
}
