use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    consts::auth_const::{ORGANIZATION_MEMBERSHIP_TABLE, ROLE_TABLE},
    errors::{Error, Result},
    middleware::UserId,
    models::{
        organization::OrganizationMembership,
        permission::{Permission, PermissionChecker},
        role::{CreateRoles, PRoles, RequestCreateRoles, RequestUpdateRoles, Roles},
    },
    state::AppState,
    utils::{
        get_record_id::get_record_id_from_string, permission_context::create_context,
        time::time_now, validated_form::ValidatedJson,
    },
};

pub async fn create_role(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Extension(UserId(user_id)): Extension<UserId>,
    ValidatedJson(input): ValidatedJson<RequestCreateRoles>,
) -> Result<(StatusCode, Json<Roles>)> {
    // * Admin creates a new role like manager, support, etc.

    let org_id = get_record_id_from_string(org_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone(), None)
        .await?
        .has_permission(&Permission::RolesCreate);
    if permission == false {
        return Err(Error::AccessDenied(Permission::RolesCreate));
    }

    let role_key = input.name.clone().to_lowercase();
    let check_role = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE name = $name AND key = $key AND organization_id = $organization_id;")
        .bind(("table", ROLE_TABLE))
        .bind(("name", input.name.clone()))
        .bind(("key", role_key.clone()))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<Roles>>(0)?;
    if let Some(_) = check_role.first() {
        return Err(Error::RoleAlreadyExist);
    };

    let role_data = CreateRoles {
        organization_id: org_id,
        name: input.name,
        key: role_key,
        description: input.description,
        permissions: input.permissions,
        is_default: false,
        is_system: false,
        created_at: time_now(),
        metadata: input.metadata,
    };
    let role = state
        .sdb
        .create::<Option<Roles>>(ROLE_TABLE)
        .content(role_data)
        .await?
        .ok_or(Error::InternalServerError)?;

    // TODO: Log role creation event

    return Ok((StatusCode::CREATED, Json(role)));
}

pub async fn read_role(
    State(_state): State<AppState>,
    Extension(UserId(_user_id)): Extension<UserId>,
) {
    // * List all available roles for an organization.
}

pub async fn update_role(
    State(state): State<AppState>,
    Path((org_id, role_id)): Path<(String, String)>,
    Extension(UserId(user_id)): Extension<UserId>,
    ValidatedJson(input): ValidatedJson<RequestUpdateRoles>,
) -> Result<(StatusCode, Json<Roles>)> {
    let org_id = get_record_id_from_string(org_id);
    let role_id = get_record_id_from_string(role_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone(), None)
        .await?
        .has_permission(&Permission::RolesUpdate);
    if permission == false {
        return Err(Error::AccessDenied(Permission::RolesUpdate));
    }

    let role = state
        .sdb
        .select::<Option<Roles>>(role_id.clone())
        .await?
        .ok_or(Error::InternalServerError)?;

    let owner = format!("{:?}", PRoles::Owner);
    if role.name == owner || role.key == owner.to_lowercase() {
        return Err(Error::Custom("Sorry cant modify owner".to_string()));
    }

    let role = state
        .sdb
        .update::<Option<Roles>>(role_id)
        .merge(input)
        .await?
        .ok_or(Error::InternalServerError)?;

    // TODO: Validate new permissions
    // TODO: Update affected memberships if needed
    // TODO: Log role update event

    return Ok((StatusCode::CREATED, Json(role)));
}

pub async fn delete_role(
    State(state): State<AppState>,
    Path((org_id, role_id)): Path<(String, String)>,
    Extension(UserId(user_id)): Extension<UserId>,
) -> Result<(StatusCode, String)> {
    // * Only if not in use. (Remove unused roles (cannot delete default or in-use roles).)

    let org_id = get_record_id_from_string(org_id);
    let role_id = get_record_id_from_string(role_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone(), None)
        .await?
        .has_permission(&Permission::RolesDelete);
    if permission == false {
        return Err(Error::AccessDenied(Permission::RolesDelete));
    }

    let role = state
        .sdb
        .select::<Option<Roles>>(role_id.clone())
        .await?
        .ok_or(Error::InternalServerError)?;

    let owner = format!("{:?}", PRoles::Owner);
    if role.name == owner || role.key == owner.to_lowercase() {
        return Err(Error::Custom("Sorry cant modify owner".to_string()));
    } else if role.is_default {
        return Err(Error::Custom("Sorry cant modify default role".to_string()));
    }

    let  org_membership = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE role = $role AND organization_id = $organization_id AND deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("role", role.name))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?;

    // reassign to viewer
    for mut member in org_membership {
        member.role = format!("{:?}", PRoles::Viewer);
        let _ = state
            .sdb
            .clone()
            .update::<Option<OrganizationMembership>>(member.id.clone())
            .content(member)
            .await?
            .ok_or(Error::InternalServerError)?;
    }

    let _ = state
        .sdb
        .delete::<Option<Roles>>(role_id)
        .await?
        .ok_or(Error::InternalServerError)?;

    // TODO: Log role deletion event

    Ok((StatusCode::OK, "Role deleted successfully".to_string()))
}
