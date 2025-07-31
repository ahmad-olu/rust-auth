use axum::{Extension, extract::State};

use crate::{middleware::UserId, state::AppState};

// Sub-groups within an organization (e.g., "Engineering", "Product").

pub async fn create_team(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {

    // * Must belong to an organization. (Any member with permission (e.g., team:create) can create a team.)

    // TODO:     Authenticate user
    // TODO: Check user has teams.create permission
    // TODO: Validate team name and slug uniqueness within org
    // TODO: Validate parent team exists if specified
    // TODO: Create team record
    // TODO: Add creator as team admin
    // TODO: Log team creation event
    // TODO: Return team data
}

pub async fn join_team(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // TODO:     Authenticate user
    // TODO: Check team visibility and join permissions
    // TODO: Validate user is organization member
    // TODO: Check if already team member
    // TODO: Create team membership
    // TODO: Log team join event
    // TODO: Return membership data
}

pub async fn read_team(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * List teams in an organization.(List teams within org or nested teams via parent_team_id.)
}

pub async fn update_team(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * Rename or reassign team manager.  Change name, privacy, settings.

    // TODO:     Authenticate user
    // TODO: Check user has team admin role or teams.update permission
    // TODO: Validate new slug uniqueness if changed
    // TODO: Update team record
    // TODO: Log team update event
    // TODO: Return updated team data
}

pub async fn delete_team(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * With care, especially if team is linked to critical data. (soft): Set deleted_at.

    // TODO:    Authenticate user
    // TODO:Check user has team admin role or teams.delete permission
    // TODO:Check for child teams (handle or prevent deletion)
    // TODO:Remove all team memberships
    // TODO:Soft delete team record
    // TODO:Log team deletion event
    // TODO:Return success confirmation
}

pub async fn add_team_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {

    // * When adding a user to a team.  Add user to a team, optionally with added_by.

    // TODO:     Authenticate user
    // TODO: Check user is team admin or has team management permissions
    // TODO: Validate target user is organization member
    // TODO: Check if already team member
    // TODO: Create team membership record
    // TODO: Log team membership creation event
    // TODO: Return membership data
}

pub async fn read_team_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * List members per team.
}

pub async fn update_team_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * Promote or demote members. Change role or permissions within team.

    // TODO:     Authenticate user
    // TODO: Check user is team admin
    // TODO: Validate new role
    // TODO: Update team membership record
    // TODO: Log role change event
    // TODO: Return updated membership data
}

pub async fn remove_team_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * When someone leaves a team. Remove user from a team.

    // TODO:     Authenticate user
    // TODO: Check user is team admin or removing themselves
    // TODO: Delete team membership record
    // TODO: Log member removal event
    // TODO: Return success confirmation
}
