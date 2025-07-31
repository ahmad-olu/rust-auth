use axum::{Extension, extract::State};

use crate::{middleware::UserId, state::AppState};

pub async fn create_role(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {

    // * Admin creates a new role like manager, support, etc.

    // TODO: Authenticate user
    // TODO: Check user has roles.create permission
    // TODO: Validate role name and key uniqueness within org
    // TODO: Validate permissions against allowed permission list
    // TODO: Create role record
    // TODO: Log role creation event
    // TODO: Return role data
}

pub async fn read_role(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * List all available roles for an organization.
}

pub async fn update_role(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * Modify permissions.

    // TODO:     Authenticate user
    // TODO: Check user has roles.update permission
    // TODO: Prevent modification of owner role
    // TODO: Validate new permissions
    // TODO: Update role record
    // TODO: Update affected memberships if needed
    // TODO: Log role update event
    // TODO: Return updated role data
}

pub async fn delete_role(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) {
    // * Only if not in use. (Remove unused roles (cannot delete default or in-use roles).)

    // TODO: Authenticate user
    // TODO: Check user has roles.delete permission
    // TODO: Prevent deletion of default roles
    // TODO: Check if role is in use by members
    // TODO: Either reassign members or prevent deletion
    // TODO: Delete role record
    // TODO: Log role deletion event
    // TODO: Return success confirmation
}
