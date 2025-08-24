use axum::{
    Extension,
    extract::{Path, State},
    http::StatusCode,
};
use tracing::info;

use crate::{
    consts::auth_const::{INVITATION_TABLE, ORGANIZATION_MEMBERSHIP_TABLE, USER_TABLE},
    errors::{Error, Result},
    middleware::UserId,
    models::{
        invitation::{CreateInvitation, Invitation, InvitationStatus},
        organization::OrganizationMembership,
        permission::{Permission, PermissionChecker},
        role::PRoles,
        user::User,
    },
    state::AppState,
    utils::{
        email_verification::generate_verification_token,
        get_record_id::get_record_id_from_string,
        permission_context::create_context,
        time::{time_now, time_now_plus_three_days},
        validated_form::ValidatedJson,
    },
};

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, validator::Validate)]
pub struct CreateSendInviteRequest {
    #[validate(email, length(min = 9, max = 255))]
    pub email: String, // ! & (len = 255)
    pub metadata: Option<serde_json::Value>,
}

pub async fn send_invitation(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path(org_id): Path<String>,
    ValidatedJson(input): ValidatedJson<CreateSendInviteRequest>,
) -> Result<(StatusCode, String)> {
    // * Admin creates an invite with role, email, optional message.

    // Invite created with a token.
    // Email sent to user.
    // User accepts → creates membership in organization_memberships.

    let org_id = get_record_id_from_string(org_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone(), None)
        .await?
        .has_any_permission(&[Permission::MembersInvite]);

    if permission == false {
        return Err(Error::AccessDenied(Permission::MembersInvite));
    }

    let user_exist_in_org = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE user_id.email = $email AND organization_id = $organization_id AND user_id.deleted_at == None;",
        )
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("email", input.email.clone()))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?.is_empty();

    if !user_exist_in_org {
        // return Err(Error::Custom(format!("User Already Exist")));
        return Ok((
            StatusCode::CREATED,
            format!("Invite sent to {}", input.email),
        ));
    }

    let user_pending_invite = state
        .sdb
        .query(
            "SELECT * FROM type::table($table) WHERE email = $email AND organization_id = $organization_id AND status = $status AND expires_at < time::now();",
        )
        .bind(("table", INVITATION_TABLE))
        .bind(("email", input.email.clone()))
        .bind(("organization_id", org_id.clone()))
        .bind(("status", InvitationStatus::Pending))
        .await?
        .take::<Vec<Invitation>>(0)?.is_empty();

    if !user_pending_invite {
        // return Err(Error::Custom(format!("User Already Exist")));
        return Ok((
            StatusCode::CREATED,
            format!("Invite sent to {}", input.email),
        ));
    }

    let token = generate_verification_token();
    let invitation_data = CreateInvitation {
        team_id: None,
        organization_id: Some(org_id.clone()),
        email: input.email.clone(),
        role: format!("{:?}", PRoles::Member),
        token: token.1,
        invite_by: user_id.clone(),
        message: None,
        status: InvitationStatus::Pending,
        expires_at: time_now_plus_three_days(),
        metadata: input.metadata,
        created_at: time_now(),
    };

    let _ = state
        .sdb
        .create::<Option<Invitation>>(INVITATION_TABLE)
        .content(invitation_data)
        .await?
        .ok_or(Error::InternalServerError)?;

    info!("Invite token = {}", token.0);
    // TODO: Send invitation email with token
    // TODO: Log invitation creation event
    // TODO: Return invitation data

    return Ok((
        StatusCode::CREATED,
        format!("Invite sent to {}", input.email),
    ));
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
    todo!()
}

pub async fn decline_invitation(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // TODO:     Validate invitation token
    // TODO: Update invitation status to declined
    // TODO: Log invitation decline event
    // TODO: Return success confirmation

    todo!()
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

    todo!()
}

pub async fn read_invitation(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * Admin lists pending/accepted invites.

    todo!()
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

    todo!()
}
