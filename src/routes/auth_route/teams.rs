use std::collections::HashSet;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    consts::auth_const::{
        ORGANIZATION_MEMBERSHIP_TABLE, TEAM_MEMBERSHIP_TABLE, TEAM_TABLE, USER_TABLE,
    },
    errors::{Error, Result},
    middleware::UserId,
    models::{
        organization::OrganizationMembership,
        permission::{
            Permission, PermissionChecker, TeamPermissionValidator, all_teams_permission,
            only_view_teams_permission,
        },
        team::{CreateTeam, CreateTeamMembership, Team, TeamMembership, TeamMembershipStatus},
        user::User,
    },
    state::AppState,
    utils::{
        get_record_id::get_record_id_from_string, permission_context::create_context,
        slug::to_slug, time::time_now, validated_form::ValidatedJson,
    },
};

// Sub-groups within an organization (e.g., "Engineering", "Product").

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, validator::Validate)]
pub struct CreateTeamRequest {
    #[validate(length(min = 9, max = 255))]
    pub name: String, // ! & (len = 255)
    #[validate(length(min = 40, max = 2000))]
    pub description: String,
    pub parent_team_id: Option<String>,      // !team id
    pub is_private: Option<bool>,            // ! (default false)
    pub settings: Option<serde_json::Value>, // ! (default {})
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
}
pub async fn create_team(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path(org_id): Path<String>,
    ValidatedJson(input): ValidatedJson<CreateTeamRequest>,
) -> Result<(StatusCode, Json<Team>)> {
    // * Must belong to an organization. (Any member with permission (e.g., team:create) can create a team.)
    let org_id = get_record_id_from_string(org_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone(), None)
        .await?
        .has_permission(&Permission::TeamsCreate);
    if permission == false {
        return Err(Error::AccessDenied(Permission::TeamsCreate));
    }
    let parent_team_id = if let Some(parent_team) = input.parent_team_id {
        let team_id = get_record_id_from_string(parent_team);
        let _ = state
            .sdb
            .select::<Option<Team>>(team_id.clone())
            .await?
            .ok_or(Error::InternalServerError)?;

        Some(team_id)
    } else {
        None
    };

    let slug = to_slug(&input.name);
    let check_team: Vec<Team> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE name = $name AND slug = $slug AND organization_id = $organization_id AND deleted_at == None;")
        .bind(("table", TEAM_TABLE))
        .bind(("name", input.name.clone()))
        .bind(("slug", slug.clone()))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take(0)?;
    if let Some(team) = check_team.first() {
        if team.name == input.name || team.slug == slug {
            return Err(Error::TeamNameTaken);
        }
    };

    let team_data = CreateTeam {
        name: input.name,
        slug,
        organization_id: org_id,
        created_by: user_id.clone(),
        description: input.description,
        parent_team_id,
        is_private: input.is_private.unwrap_or(false),
        settings: input.settings,
        metadata: input.metadata,
        created_at: time_now(),
        deleted_at: None,
        updated_at: None,
    };
    let team = state
        .sdb
        .create::<Option<Team>>(TEAM_TABLE)
        .content(team_data)
        .await?;
    if let Some(team) = team.clone() {
        let permissions = all_teams_permission();
        let membership_data = CreateTeamMembership {
            team_id: team.id,
            organization_id: team.organization_id,
            user_id: user_id.clone(),
            status: TeamMembershipStatus::Active,
            permissions,
            metadata: None,
            joined_at: time_now(),
            added_by: None,
            created_at: time_now(),
            updated_at: None,
            deleted_at: None,
        };
        let _ = state
            .sdb
            .create::<Option<TeamMembership>>(TEAM_MEMBERSHIP_TABLE)
            .content(membership_data)
            .await?
            .ok_or(Error::InternalServerError)?;
    }

    // TODO: Log team creation event

    return Ok((
        StatusCode::CREATED,
        Json(team.ok_or(Error::InternalServerError)?),
    ));
}

pub async fn join_team(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path((org_id, team_id)): Path<(String, String)>,
) -> Result<(StatusCode, TeamMembership)> {
    let org_id = get_record_id_from_string(org_id);
    let team_id = get_record_id_from_string(team_id);

    let team= state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE team_id = $team_id AND user_id = $user_id AND organization_id = $organization_id AND deleted_at == None;")
        .bind(("table", TEAM_MEMBERSHIP_TABLE))
        .bind(("team_id", team_id.clone()))
        .bind(("user_id", user_id.clone()))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<TeamMembership>>(0)?; // already a member

    if team.first().is_some() {
        return Err(Error::InternalServerError);
    }

    let _ = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE id = $id AND organization_id = $organization_id AND is_private = true AND deleted_at == None;")
        .bind(("table", TEAM_TABLE))
        .bind(("id", team_id.clone()))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<Team>>(0)?.first().ok_or(Error::InternalServerError)?.clone(); //team is public

    let _= state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE team_id = $team_id AND user_id = $user_id AND organization_id = $organization_id AND deleted_at == None;")
        .bind(("table", TEAM_MEMBERSHIP_TABLE))
        .bind(("team_id", team_id.clone()))
        .bind(("user_id", user_id.clone()))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<TeamMembership>>(0)?
        .first()
        .ok_or(Error::InternalServerError)?; // already a member
    let _= state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE user_id = $user_id AND organization_id = $organization_id AND deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("user_id", user_id.clone()))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?.first().ok_or(Error::InternalServerError)?; // member of org
    let permissions = only_view_teams_permission();
    let team_data = CreateTeamMembership {
        team_id,
        organization_id: org_id,
        user_id,
        status: TeamMembershipStatus::Active,
        permissions,
        metadata: None,
        joined_at: time_now(),
        added_by: None,
        created_at: time_now(),
        updated_at: None,
        deleted_at: None,
    };
    let member = state
        .sdb
        .create::<Option<TeamMembership>>(TEAM_MEMBERSHIP_TABLE)
        .content(team_data)
        .await?
        .ok_or(Error::InternalServerError)?;
    // TODO: Log team join event
    // TODO: Return membership data
    //
    Ok((StatusCode::CREATED, member))
}

pub async fn read_team(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    State(org_id): State<String>,
) -> Result<(StatusCode, Json<Vec<Team>>)> {
    // * List teams in an organization.(List teams within org or nested teams via parent_team_id.)

    let org_id = get_record_id_from_string(org_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone(), None)
        .await?
        .has_permission(&Permission::TeamsRead);
    if permission == false {
        return Err(Error::AccessDenied(Permission::TeamsRead));
    }

    let team = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND deleted_at == None")
        .bind(("table", TEAM_TABLE))
        .bind(("organization_id", org_id))
        .await?
        .take::<Vec<Team>>(0)?;

    Ok((StatusCode::OK, Json(team)))
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct UpdateTeamRequest {
    pub name: Option<String>, // ! & (len = 255)
    pub description: Option<String>,
    pub is_private: Option<bool>,            // ! (default false)
    pub settings: Option<serde_json::Value>, // ! (default {})
    pub metadata: Option<serde_json::Value>,
}

impl UpdateTeamRequest {
    fn apply_to(&self, team: &mut Team) {
        if let Some(name) = &self.name {
            let slug = to_slug(&name);
            team.name = name.clone();
            team.slug = slug;
        }
        if let Some(description) = &self.description {
            team.description = description.clone();
        }
        if let Some(is_private) = &self.is_private {
            team.is_private = *is_private;
        }
        if let Some(settings) = &self.settings {
            team.settings = Some(settings.clone());
        }
        if let Some(metadata) = &self.metadata {
            team.metadata = Some(metadata.clone())
        }
    }
}

pub async fn update_team(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path((org_id, team_id)): Path<(String, String)>,
    ValidatedJson(input): ValidatedJson<UpdateTeamRequest>,
) -> Result<(StatusCode, Json<Team>)> {
    // * Rename or reassign team manager.  Change name, privacy, settings.

    let org_id = get_record_id_from_string(org_id);
    let team_id = get_record_id_from_string(team_id);
    let permission = create_context(
        &state.sdb,
        user_id.clone(),
        org_id.clone(),
        Some(team_id.clone()),
    )
    .await?
    .has_permission(&Permission::TeamsUpdate);
    if permission == false {
        return Err(Error::AccessDenied(Permission::TeamsUpdate));
    }

    let mut team = state
        .sdb
        .select::<Option<Team>>(team_id.clone())
        .await?
        .ok_or(Error::InternalServerError)?;
    if let Some(name) = &input.name {
        let slug = to_slug(&name);
        if team.slug == slug {
            return Err(Error::TeamNameTaken);
        }
    }
    input.apply_to(&mut team);
    let team = state
        .sdb
        .update::<Option<Team>>(team_id)
        .content(team)
        .await?
        .ok_or(Error::InternalServerError)?;

    // TODO: Log team update event

    Ok((StatusCode::CREATED, Json(team)))
}

pub async fn delete_team(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path((org_id, team_id)): Path<(String, String)>,
) -> Result<(StatusCode, String)> {
    // * With care, especially if team is linked to critical data. (soft): Set deleted_at.

    let org_id = get_record_id_from_string(org_id);
    let team_id = get_record_id_from_string(team_id);
    let permission = create_context(
        &state.sdb,
        user_id.clone(),
        org_id.clone(),
        Some(team_id.clone()),
    )
    .await?
    .has_permission(&Permission::TeamsDelete);
    if permission == false {
        return Err(Error::AccessDenied(Permission::TeamsDelete));
    }
    let mut memberships = state.sdb
    .query("SELECT * FROM type::table($table) WHERE team_id = $team_id AND organization_id = $organization_id AND deleted_at == None;")
    .bind(("table", TEAM_MEMBERSHIP_TABLE))
    .bind(("organization_id", org_id.clone()))
    .bind(("team_id", team_id.clone()))
    .await?.take::<Vec<TeamMembership>>(0)?;
    for member in memberships.iter_mut() {
        member.deleted_at = Some(time_now());
        member.updated_at = Some(time_now());
        let _ = state
            .sdb
            .update::<Option<TeamMembership>>(member.id.clone())
            .content(member.clone())
            .await?;
    }

    let mut team = state
        .sdb
        .select::<Option<Team>>(team_id.clone())
        .await?
        .ok_or(Error::InternalServerError)?;
    team.deleted_at = Some(time_now());
    team.updated_at = Some(time_now());
    let _ = state
        .sdb
        .update::<Option<Team>>(team_id)
        .content(team)
        .await?;

    // TODO:Check for child teams (handle or prevent deletion)
    // TODO:Log team deletion event

    Ok((StatusCode::OK, "Team deleted Successfully".to_string()))
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct AddTeamMembershipRequest {
    pub email: String,
    pub permissions: HashSet<Permission>,
    pub metadata: Option<serde_json::Value>,
}

pub async fn add_team_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path((org_id, team_id)): Path<(String, String)>,
    ValidatedJson(input): ValidatedJson<AddTeamMembershipRequest>,
) -> Result<(StatusCode, Json<TeamMembership>)> {
    let _ = input.permissions.validate_team_permissions()?;

    let org_id = get_record_id_from_string(org_id);
    let team_id = get_record_id_from_string(team_id);
    let permission = create_context(
        &state.sdb,
        user_id.clone(),
        org_id.clone(),
        Some(team_id.clone()),
    )
    .await?
    .has_any_permission(&[Permission::TeamsCreate, Permission::TeamsJoin]);

    if permission == false {
        return Err(Error::AccessDenied(Permission::TeamsJoin));
    }
    let new_user = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE email = $email AND deleted_at == None;")
        .bind(("table", USER_TABLE))
        .bind(("email", input.email))
        .await?
        .take::<Vec<User>>(0)?
        .first()
        .ok_or(Error::InternalServerError)?
        .clone();

    let _check_user_org_membership = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE user_id = $user_id AND organization_id = $organization_id AND deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("user_id", new_user.id.clone()))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?
        .first()
        .ok_or(Error::InternalServerError)?
        .clone();

    let mut check_user_org_team_membership = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE user_id = $user_id AND team_id = $team_id AND organization_id = $organization_id AND deleted_at == None;")
        .bind(("table", TEAM_MEMBERSHIP_TABLE))
        .bind(("user_id", new_user.id.clone()))
        .bind(("organization_id", org_id.clone()))
        .bind(("team_id", team_id.clone()))
        .await?;
    if let Some(res) = check_user_org_team_membership
        .take::<Vec<TeamMembership>>(0)?
        .first()
    {
        return Ok((StatusCode::CREATED, Json(res.clone())));
    } else {
        let new_user_data = CreateTeamMembership {
            added_by: Some(user_id.clone()),
            created_at: time_now(),
            deleted_at: None,
            joined_at: time_now(),
            metadata: input.metadata,
            organization_id: org_id,
            permissions: Some(input.permissions),
            status: TeamMembershipStatus::Active,
            team_id: team_id,
            user_id: new_user.id,
            updated_at: None,
        };
        let res = state
            .sdb
            .create::<Option<TeamMembership>>(TEAM_MEMBERSHIP_TABLE)
            .content(new_user_data)
            .await?
            .ok_or(Error::InternalServerError)?;

        // TODO: Log team membership creation event

        return Ok((StatusCode::CREATED, Json(res)));
    };
}

pub async fn read_team_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path((org_id, team_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<Vec<TeamMembership>>)> {
    let org_id = get_record_id_from_string(org_id);
    let team_id = get_record_id_from_string(team_id);
    let permission = create_context(
        &state.sdb,
        user_id.clone(),
        org_id.clone(),
        Some(team_id.clone()),
    )
    .await?
    .has_permission(&Permission::TeamsRead);

    if permission == false {
        return Err(Error::AccessDenied(Permission::TeamsRead));
    }

    let team_membership = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE team_id = $team_id AND organization_id = $organization_id AND deleted_at == None;")
        .bind(("table", TEAM_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("team_id", team_id.clone()))
        .await?.take::<Vec<TeamMembership>>(0)?;
    // ?TODO: pagination
    return Ok((StatusCode::OK, Json(team_membership)));
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct UpdateTeamMembershipRequest {
    pub status: Option<TeamMembershipStatus>,
    pub permissions: Option<HashSet<Permission>>,
    pub metadata: Option<serde_json::Value>,
}

impl UpdateTeamMembershipRequest {
    fn apply_to(&self, team: &mut TeamMembership) {
        if let Some(status) = &self.status {
            team.status = status.clone();
        }
        if let Some(permissions) = &self.permissions {
            team.permissions = Some(permissions.clone());
        }
        if let Some(metadata) = &self.metadata {
            team.metadata = Some(metadata.clone());
        }
    }
}

pub async fn update_team_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path((org_id, team_id, team_member_id)): Path<(String, String, String)>,
    ValidatedJson(input): ValidatedJson<UpdateTeamMembershipRequest>,
) -> Result<(StatusCode, Json<TeamMembership>)> {
    // * Promote or demote members. Change role or permissions within team.

    if let Some(permissions) = &input.permissions {
        let _ = permissions.validate_team_permissions()?;
    }

    let org_id = get_record_id_from_string(org_id);
    let team_id = get_record_id_from_string(team_id);
    let team_membership_id = get_record_id_from_string(team_member_id);
    let permission = create_context(
        &state.sdb,
        user_id.clone(),
        org_id.clone(),
        Some(team_id.clone()),
    )
    .await?
    .has_permission(&Permission::TeamsUpdate);

    if permission == false {
        return Err(Error::AccessDenied(Permission::TeamsUpdate));
    }

    let mut membership = state
        .sdb
        .select::<Option<TeamMembership>>(team_membership_id.clone())
        .await?
        .ok_or(Error::InternalServerError)?;

    input.apply_to(&mut membership);
    let res = state
        .sdb
        .update::<Option<TeamMembership>>(team_membership_id)
        .content(membership)
        .await?
        .ok_or(Error::InternalServerError)?;

    // TODO: Log role change event

    Ok((StatusCode::OK, Json(res)))
}

pub async fn remove_team_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path((org_id, team_id, team_member_id)): Path<(String, String, String)>,
) -> Result<(StatusCode, String)> {
    // * When someone leaves a team. Remove user from a team.

    let org_id = get_record_id_from_string(org_id);
    let team_id = get_record_id_from_string(team_id);
    let team_membership_id = get_record_id_from_string(team_member_id);
    let permission = create_context(
        &state.sdb,
        user_id.clone(),
        org_id.clone(),
        Some(team_id.clone()),
    )
    .await?
    .has_permission(&Permission::TeamsUpdate);

    if permission == false {
        return Err(Error::AccessDenied(Permission::TeamsUpdate));
    }

    // ? Check user is team admin or removing themselves
    let mut membership = state
        .sdb
        .select::<Option<TeamMembership>>(team_membership_id.clone())
        .await?
        .ok_or(Error::InternalServerError)?;
    membership.deleted_at = Some(time_now());

    let _ = state
        .sdb
        .update::<Option<TeamMembership>>(team_membership_id)
        .content(membership)
        .await?
        .ok_or(Error::InternalServerError)?;

    // TODO: Log member removal event

    Ok((StatusCode::OK, "Delete membership confirmed".to_string()))
}
