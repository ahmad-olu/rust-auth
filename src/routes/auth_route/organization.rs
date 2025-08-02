use std::collections::HashSet;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use regex::Regex;
use surrealdb::RecordId;
use validator::Validate;

use crate::{
    consts::auth_const::{
        INVITATION_TABLE, ORGANIZATION_MEMBERSHIP_TABLE, ORGANIZATION_TABLE, ROLE_TABLE,
        TEAM_MEMBERSHIP_TABLE, TEAM_TABLE, USER_TABLE,
    },
    middleware::UserId,
    models::{
        invitation::{Invitation, InvitationStatus},
        organization::{
            CreateOrganization, CreateOrganizationMembership, Organization, OrganizationMembership,
            OrganizationMembershipStatus,
        },
        permission::{Permission, PermissionChecker},
        role::{PRoles, Roles, contains_default_role, inti_roles},
        team::{Team, TeamMembership, TeamMembershipStatus},
        user::User,
    },
    state::AppState,
    utils::{
        get_record_id::get_record_id_from_string, permission_context::create_context,
        slug::to_slug, time::time_now, validated_form::ValidatedJson,
    },
};

use crate::errors::{Error, Result};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Validate)]
pub struct CreateOrgRequest {
    #[validate(length(min = 9, max = 255))]
    pub name: String,
    #[validate(length(min = 40, max = 2000))]
    pub description: String,
    pub logo_url: Option<String>,
    pub website_url: Option<String>,
    pub settings: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

pub async fn create_organization(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    ValidatedJson(input): ValidatedJson<CreateOrgRequest>,
) -> Result<(StatusCode, Json<Organization>)> {
    let slug = to_slug(&input.name);
    let check_org: Vec<Organization> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE name = $name AND deleted_at == None;")
        .bind(("table", ORGANIZATION_TABLE))
        .bind(("name", input.name.clone()))
        .await?
        .take(0)?;
    if let Some(org) = check_org.first() {
        if org.name == input.name || org.slug == slug {
            return Err(Error::OrgNameTaken);
        }
    };
    let user_org_limit: Vec<Organization> = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE created_by = $id AND deleted_at == None;")
        .bind(("table", ORGANIZATION_TABLE))
        .bind(("id", user_id.clone()))
        .await?
        .take(0)?;
    if user_org_limit.len() >= 5 {
        return Err(Error::OrgCreationLimitReached);
    }

    let org_data = CreateOrganization {
        name: input.name,
        slug,
        created_by: user_id.clone(),
        blocked: false,
        created_at: time_now(),
        description: input.description,
        logo_url: input.logo_url,
        metadata: input.metadata,
        settings: input.settings,
        website_url: input.website_url,
    };

    let org: Organization = state
        .sdb
        .create(ORGANIZATION_TABLE)
        .content(org_data)
        .await?
        .ok_or(Error::InternalServerError)?;

    let mut permission = HashSet::new();
    permission.insert(Permission::All);

    let org_member_data = CreateOrganizationMembership {
        created_at: time_now(),
        invited_by: None,
        joined_at: Some(time_now()),
        metadata: None,
        organization_id: org.clone().id,
        role: format!("{:?}", PRoles::Owner),
        custom_permissions: Some(permission),
        status: OrganizationMembershipStatus::Active,
        user_id,
    };

    let _ = inti_roles(&state.sdb, org.clone().id).await?; // ? default roles
    let _ = state
        .sdb
        .create::<Option<OrganizationMembership>>(ORGANIZATION_MEMBERSHIP_TABLE)
        .content(org_member_data)
        .await?
        .ok_or(Error::InternalServerError)?;

    // TODO: Create organization record
    // TODO: Create owner membership for creator
    // TODO: Initialize organization settings
    // TODO: Log organization creation event
    // TODO: Return organization data
    //todo!()
    return Ok((StatusCode::CREATED, Json(org)));
}

pub async fn read_organization(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path(id_or_slug): Path<String>,
) -> Result<(StatusCode, Json<Organization>)> {
    if Regex::new(r"^[a-zA-Z_]+:[\w\-]+$")
        .unwrap()
        .is_match(&id_or_slug)
    {
        let id = get_record_id_from_string(id_or_slug);
        let org = state
            .sdb
            .query("SELECT * FROM type::table($table1) WHERE id = $id AND deleted_at == NONE;")
            .bind(("table1", ORGANIZATION_TABLE))
            .bind(("id", id))
            .bind(("user_id", user_id.clone()))
            .await?
            .take::<Vec<Organization>>(0)?
            .first()
            .ok_or(Error::InternalServerError)?
            .clone();

        let permission = create_context(&state.sdb, user_id.clone(), org.id.clone())
            .await?
            .has_permission(&Permission::OrgRead);

        if permission == false {
            return Err(Error::AccessDenied(Permission::OrgRead));
        }
        return Ok((StatusCode::OK, Json(org.clone())));
    } else {
        let org = state
            .sdb
            .query("SELECT * FROM type::table($table1) WHERE slug = $slug AND deleted_at == NONE;")
            .bind(("table1", ORGANIZATION_TABLE))
            .bind(("slug", id_or_slug))
            .bind(("user_id", user_id.clone()))
            .await?
            .take::<Vec<Organization>>(0)?
            .first()
            .ok_or(Error::InternalServerError)?
            .clone();
        let permission = create_context(&state.sdb, user_id.clone(), org.id.clone())
            .await?
            .has_permission(&Permission::OrgRead);
        if permission == false {
            return Err(Error::AccessDenied(Permission::OrgRead));
        }
        return Ok((StatusCode::OK, Json(org.clone())));
    }
}

pub async fn read_organizations(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) -> Result<(StatusCode, Json<Vec<Organization>>)> {
    // let page = 2;
    // let per_page = 10;
    // let start = (page - 1) * per_page;

    let org: Vec<Organization> = state
        .sdb
        .query(
            r#"
            (SELECT organization_id.* as org, custom_permissions, role 
            FROM type::table($table2)
            WHERE user_id = $user_id
              AND (
                custom_permissions CONTAINSANY $permissions OR custom_permissions CONTAINSANY ['All']
                   OR
                !(
                    SELECT * FROM type::table($table1) WHERE organization_id = $parent.organization_id AND name = $parent.role
                ).is_empty()
              )
            START $start
            LIMIT $limit).map(|$r| $r.org);
            "#,
        )
        .bind(("table1", ROLE_TABLE))
        .bind(("table2", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("user_id", user_id))
        .bind(("permissions", [Permission::OrgRead]))
        .bind(("start", 0))
        .bind(("limit", 25))
        .await?
        .take(0)?;
    Ok((StatusCode::OK, Json(org)))
}

#[derive(serde::Deserialize, Debug, Clone, Validate)]
pub struct UpdateOrganization {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 9, max = 255))]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 40, max = 2000))]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl UpdateOrganization {
    pub fn apply_to(&self, org: &mut Organization) {
        if let Some(name) = &self.name {
            let slug = to_slug(&name);
            org.name = name.clone();
            org.slug = slug;
        }
        if let Some(description) = &self.description {
            org.description = description.clone();
        }
        if let Some(logo_url) = &self.logo_url {
            org.logo_url = Some(logo_url.clone());
        }
        if let Some(website_url) = &self.website_url {
            org.website_url = Some(website_url.clone());
        }
        if let Some(settings) = &self.settings {
            org.settings = Some(settings.clone());
        }
        if let Some(metadata) = &self.metadata {
            org.metadata = Some(metadata.clone());
        }
    }
}

pub async fn update_organization(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path(org_id): Path<String>,
    ValidatedJson(input): ValidatedJson<UpdateOrganization>,
) -> Result<(StatusCode, Json<Organization>)> {
    let org_id = get_record_id_from_string(org_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone())
        .await?
        .has_permission(&Permission::OrgUpdate);
    if permission == false {
        return Err(Error::AccessDenied(Permission::OrgUpdate));
    }

    if let Some(mut org) = state
        .sdb
        .select::<Option<Organization>>(org_id.clone())
        .await?
    {
        if let Some(name) = &input.name {
            let slug = to_slug(name);
            let check_org: Vec<Organization> = state
                .sdb
                .query(
                    "SELECT * FROM type::table($table) WHERE name = $name AND deleted_at == None;",
                )
                .bind(("table", ORGANIZATION_TABLE))
                .bind(("name", input.name.clone()))
                .await?
                .take(0)?;
            if let Some(org) = check_org.first() {
                if org.name == name.to_owned() || org.slug == slug {
                    return Err(Error::OrgNameTaken);
                }
            };
        }

        input.apply_to(&mut org);

        let res = state
            .sdb
            .update::<Option<Organization>>(org_id)
            .content(org)
            .await?
            .ok_or(Error::InternalServerError)
            .map(|r| (StatusCode::CREATED, Json(r)));

        // * Only Admins or Owner can rename or configure.
        // TODO: Log organization update event
        // TODO: Return updated organization data
        return res;
    } else {
        return Err(Error::InternalServerError);
    };
}

pub async fn delete_organization(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path(org_id): Path<String>,
) -> Result<(StatusCode, String)> {
    let org_id = get_record_id_from_string(org_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone())
        .await?
        .has_permission(&Permission::OrgDelete);
    if permission == false {
        return Err(Error::AccessDenied(Permission::OrgDelete));
    }
    let mut org_invitations = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND organization_id.deleted_at == None;")
        .bind(("table", INVITATION_TABLE))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<Invitation>>(0)?;
    for invitations in org_invitations.iter_mut() {
        invitations.status = InvitationStatus::Cancelled;
        let _ = state
            .sdb
            .update::<Option<Invitation>>(invitations.id.clone())
            .content(invitations.clone())
            .await?;
    }

    let mut team_members = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND organization_id.deleted_at == None;")
        .bind(("table", TEAM_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<TeamMembership>>(0)?;
    for member in team_members.iter_mut() {
        member.status = TeamMembershipStatus::InActive;
        member.deleted_at = Some(time_now());
        let _ = state
            .sdb
            .update::<Option<TeamMembership>>(member.id.clone())
            .content(member.clone())
            .await?;
    }

    let mut org_members = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND organization_id.deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?;
    for members in org_members.iter_mut() {
        members.status = OrganizationMembershipStatus::InActive;
        members.deleted_at = Some(time_now());
        let _ = state
            .sdb
            .update::<Option<OrganizationMembership>>(members.id.clone())
            .content(members.clone())
            .await?;
    }

    let mut teams = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND organization_id.deleted_at == None;")
        .bind(("table", TEAM_TABLE))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<Team>>(0)?;
    for team in teams.iter_mut() {
        team.deleted_at = Some(time_now());
        let _ = state
            .sdb
            .update::<Option<Team>>(team.id.clone())
            .content(team.clone())
            .await?;
    }

    let mut roles = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND organization_id.deleted_at == None;")
        .bind(("table", ROLE_TABLE))
        .bind(("organization_id", org_id.clone()))
        .await?
        .take::<Vec<Roles>>(0)?;
    for role in roles.iter_mut() {
        role.deleted_at = Some(time_now());
        let _ = state
            .sdb
            .update::<Option<Roles>>(role.id.clone())
            .content(role.clone())
            .await?;
    }

    let mut org = state
        .sdb
        .select::<Option<Organization>>(org_id.clone())
        .await?
        .ok_or(Error::InternalServerError)?;
    org.deleted_at = Some(time_now());
    let _ = state
        .sdb
        .update::<Option<Organization>>(org_id)
        .content(org)
        .await?;

    // TODO: Schedule data cleanup job
    // TODO: Log organization deletion event
    // TODO: Return success confirmation

    Ok((StatusCode::OK, format!("organization deleted successfully")))
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, Validate)]
pub struct CreateOrganizationMembership2 {
    #[validate(email)]
    pub email: String,
    pub role: String, // ! (default member) & (less than 50)

    // ? metadata
    pub custom_permissions: Option<HashSet<Permission>>, // !  Permissions (can override role permissions)
    pub metadata: Option<serde_json::Value>,
}

impl CreateOrganizationMembership2 {
    pub fn apply_to(self, user_id: RecordId, org_id: RecordId) -> CreateOrganizationMembership {
        CreateOrganizationMembership {
            user_id,
            created_at: time_now(),
            custom_permissions: self.custom_permissions,
            invited_by: None,
            joined_at: None,
            metadata: self.metadata,
            organization_id: org_id,
            role: self.role,
            status: OrganizationMembershipStatus::Active,
        }
    }
}

pub async fn create_organization_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path(org_id): Path<String>,
    ValidatedJson(input): ValidatedJson<CreateOrganizationMembership2>,
) -> Result<(StatusCode, Json<OrganizationMembership>)> {
    let org_id = get_record_id_from_string(org_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone())
        .await?
        .has_permission(&Permission::MembersInvite);
    if permission == false {
        return Err(Error::AccessDenied(Permission::MembersInvite));
    }

    let _ = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND name = $name AND deleted_at == None;")
        .bind(("table", ROLE_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("name", input.role.clone()))
        .await?
        .take::<Vec<Roles>>(0)?
        .first()
        .ok_or(Error::Custom(format!("Role: {} does not exist in the organization. Create a role then the member", &input.role)))?;

    let user = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE email = $email AND deleted_at == None;")
        .bind(("table", USER_TABLE))
        .bind(("email", input.email.clone()))
        .await?
        .take::<Vec<User>>(0)?
        .first()
        .ok_or(Error::InternalServerError)?
        .clone();

    if let Some(member) = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND user_id = $user_id AND deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("user_id", user.id.clone()))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?
        .first() {
        return Ok((StatusCode::CREATED, Json(member.clone())));
    }

    let member = input.apply_to(user.id, org_id);
    let member = state
        .sdb
        .create::<Option<OrganizationMembership>>(ORGANIZATION_MEMBERSHIP_TABLE)
        .content(member)
        .await?
        .ok_or(Error::InternalServerError)?;

    // TODO: Send welcome notification to new member
    // TODO: Log membership creation event
    // TODO: Return membership data
    return Ok((StatusCode::CREATED, Json(member)));
}

pub async fn read_organization_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path(org_id): Path<String>,
) -> Result<(StatusCode, Json<Vec<OrganizationMembership>>)> {
    // let page = 2;
    // let per_page = 10;
    // let start = (page - 1) * per_page;
    let org_id = get_record_id_from_string(org_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone())
        .await?
        .has_permission(&Permission::MembersRead);
    if permission == false {
        return Err(Error::AccessDenied(Permission::MembersRead));
    }

    let org_memberships = state
        .sdb
        .query("SELECT * FROM type::table($table) 
            WHERE organization_id = $organization_id AND name = $name AND organization_id.deleted_at == None
            START $start
            LIMIT $limit;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("start", 0))
        .bind(("limit", 25))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?;

    return Ok((StatusCode::OK, Json(org_memberships)));
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct UpdateOrganizationMembership {
    pub role: Option<String>,
    pub custom_permissions: Option<HashSet<Permission>>,
    pub metadata: Option<serde_json::Value>,
}

impl UpdateOrganizationMembership {
    pub fn apply_to(self, org: &mut OrganizationMembership) {
        if let Some(role) = &self.role {
            org.role = role.clone();
        }
        if let Some(permission) = &self.custom_permissions {
            org.custom_permissions = Some(permission.clone());
        }
        if let Some(metadata) = &self.metadata {
            org.metadata = Some(metadata.clone());
        }
        org.updated_at = Some(time_now());
    }
}

pub async fn update_organization_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(input): Json<UpdateOrganizationMembership>,
) -> Result<(StatusCode, Json<OrganizationMembership>)> {
    let org_id = get_record_id_from_string(org_id);
    let member_id = get_record_id_from_string(member_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone())
        .await?
        .has_permission(&Permission::MembersUpdate);
    if permission == false {
        return Err(Error::AccessDenied(Permission::MembersRead));
    }

    if let Some(role) = input.role.clone() {
        if contains_default_role(&role) == true {
            return Err(Error::Custom(format!(
                "val role:{} is a reserved keyword, pick another that fits your need",
                &role
            )));
        }

        if state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND user_id = $user_id AND deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("user_id", member_id.clone()))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?
        .first().ok_or(Error::InternalServerError)?.clone().role == format!("{:?}", PRoles::Owner) && user_id == member_id {
            return Err(Error::Custom(format!("Owner Cannot Change role... pele")));
        }
        let _ = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND name = $name AND deleted_at == None;")
        .bind(("table", ROLE_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("name", role.clone()))
        .await?
        .take::<Vec<Roles>>(0)?
        .first()
        .ok_or(Error::Custom(format!("Role: {} does not exist in the organization. Create a role then the member", &role)))?;
    }
    let mut member = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND id = $id AND deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("id", member_id.clone()))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?
        .first()
        .ok_or(Error::InternalServerError)?.clone();
    input.apply_to(&mut member);
    let member = state
        .sdb
        .update::<Option<OrganizationMembership>>(member.id.clone())
        .content(member)
        .await?
        .ok_or(Error::InternalServerError)?;
    // TODO: Log role change event
    // TODO: Notify affected user of role change
    // TODO: Return updated membership data

    Ok((StatusCode::CREATED, Json(member)))
}

pub async fn delete_organization_memberships(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<(StatusCode, String)> {
    let org_id = get_record_id_from_string(org_id);
    let member_id = get_record_id_from_string(member_id);
    let permission = create_context(&state.sdb, user_id.clone(), org_id.clone())
        .await?
        .has_permission(&Permission::MembersRemove);
    if permission == false {
        return Err(Error::AccessDenied(Permission::MembersRemove));
    }

    let members = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND role = $role AND deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("role", format!("{:?}", PRoles::Owner)))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?;
    let is_user_sole_owner =
        members.len() == 1 && members[0].user_id == member_id && user_id == member_id;
    if is_user_sole_owner {
        return Err(Error::Custom(
            "You cannot remove or downgrade the only Owner of the organization.".into(),
        ));
    }

    let mut member = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND user_id = $user_id AND deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("user_id", member_id.clone()))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?
        .first().ok_or(Error::InternalServerError)?.clone();
    if member.role == format!("{:?}", PRoles::Owner) && user_id == member_id {
        return Err(Error::Custom(format!("Owner Cannot Change role... pele")));
    }
    member.status = OrganizationMembershipStatus::InActive;
    member.deleted_at = Some(time_now());

    let mut team_members = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND user_id = $user_id AND organization_id.deleted_at == None;")
        .bind(("table", TEAM_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("user_id", member_id.clone()))
        .await?
        .take::<Vec<TeamMembership>>(0)?;
    for member in team_members.iter_mut() {
        member.status = TeamMembershipStatus::InActive;
        member.deleted_at = Some(time_now());
        let _ = state
            .sdb
            .update::<Option<TeamMembership>>(member.id.clone())
            .content(member.clone())
            .await?;
    }

    let _ = state
        .sdb
        .update::<Option<OrganizationMembership>>(member.id.clone())
        .content(member.clone())
        .await?
        .ok_or(Error::InternalServerError)?;

    // TODO: Log member removal event
    // TODO: Notify removed user

    Ok((StatusCode::OK, format!("Deleted successfully")))
}

pub async fn leave_organization(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
    Path(org_id): Path<String>,
) -> Result<(StatusCode, String)> {
    let members = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND role = $role AND deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("role", format!("{:?}", PRoles::Owner)))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?;
    let is_user_sole_owner = members.len() == 1 && members[0].user_id == user_id;
    if is_user_sole_owner {
        return Err(Error::Custom(
            "You cannot remove or downgrade the only Owner of the organization.".into(),
        ));
    }

    let mut member = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND user_id = $user_id AND deleted_at == None;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("user_id", user_id.clone()))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?
        .first().ok_or(Error::InternalServerError)?.clone();

    member.status = OrganizationMembershipStatus::InActive;
    member.deleted_at = Some(time_now());

    let mut team_members = state
        .sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND user_id = $user_id AND organization_id.deleted_at == None;")
        .bind(("table", TEAM_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("user_id", user_id.clone()))
        .await?
        .take::<Vec<TeamMembership>>(0)?;
    for member in team_members.iter_mut() {
        member.status = TeamMembershipStatus::InActive;
        member.deleted_at = Some(time_now());
        let _ = state
            .sdb
            .update::<Option<TeamMembership>>(member.id.clone())
            .content(member.clone())
            .await?;
    }

    let _ = state
        .sdb
        .update::<Option<OrganizationMembership>>(member.id.clone())
        .content(member.clone())
        .await?
        .ok_or(Error::InternalServerError)?;

    // TODO: Log leave event
    // TODO: Return success confirmation
    Ok((StatusCode::OK, format!("Left Organization successfully")))
}

// ! --- extras

pub async fn organization_switch(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) -> Result<(StatusCode, String)> {
    // TODO:      Authenticate user session
    // TODO:  Validate user has membership in target organization
    // TODO:  Update session organization context
    // TODO:  Log organization switch event
    // TODO:  Return new organization context data
    todo!()
}

pub async fn bulk_member_import(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) -> Result<(StatusCode, String)> {
    //TODO:      Authenticate user
    //TODO:  Check bulk import permissions
    //TODO:  Validate CSV/JSON format
    //TODO:  Process each user record
    //TODO:  Create invitations for non-existing users
    //TODO:  Create memberships for existing users
    //TODO:  Generate import summary report
    //TODO:  Log bulk import event
    //TODO:  Return import results
    todo!()
}

pub async fn data_export(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) -> Result<(StatusCode, String)> {
    //TODO:      Authenticate user as organization owner
    //TODO:  Generate comprehensive data export
    //TODO:  Include all organization-related data
    //TODO:  Ensure data privacy compliance
    //TODO:  Create downloadable archive
    //TODO:  Log data export event
    //TODO:  Return download link with expiration
    todo!()
}

pub async fn organization_migration(
    State(state): State<AppState>,
    Extension(UserId(user_id)): Extension<UserId>,
) -> Result<(StatusCode, String)> {
    //TODO:      Authenticate as system admin
    //TODO:  Create backup of source organization
    //TODO:  Create new organization structure
    //TODO:  Migrate users and memberships
    //TODO:  Update all related records
    //TODO:  Validate data integrity
    //TODO:  Log migration events
    //TODO:  Return migration summary
    todo!()
}

#[cfg(test)]
mod user_tests {
    use std::sync::Mutex;

    use axum::{
        body::Body,
        http::{
            Request, StatusCode,
            header::{AUTHORIZATION, CONTENT_TYPE},
        },
    };
    use http_body_util::BodyExt;
    use once_cell::sync::Lazy;
    use serde_json::json;
    use surrealdb::RecordId;
    use tower::ServiceExt; // for `collect`

    use crate::{
        app,
        consts::auth_const::{
            AUTH_PASSWORD_TABLE, ORGANIZATION_MEMBERSHIP_TABLE, ORGANIZATION_TABLE, ROLE_TABLE,
            USER_TABLE,
        },
        models::organization::{Organization, OrganizationMembership},
        routes::auth_route::{
            organization::{CreateOrgRequest, CreateOrganizationMembership2},
            user::SignInFormResponse,
        },
        state::AppState,
    };

    const SIGN_UP_URI: &str = "/auth/signup";
    const SIGN_IN_URI: &str = "/auth/signin";

    static JWT_TOKEN_1: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));
    static JWT_TOKEN_2: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

    static ORG_ID: Lazy<Mutex<Option<RecordId>>> = Lazy::new(|| Mutex::new(None));
    static MEMBER_ID: Lazy<Mutex<Option<RecordId>>> = Lazy::new(|| Mutex::new(None));

    const ADMIN_FORM_SIGNUP_DATA: &str =
        "email=alana3%40gmail.com&username=allana3&password=Allana%24n09878";
    const ADMIN_FORM_SIGNIN_DATA: &str = "email=alana3%40gmail.com&password=Allana%24n09878";

    const MEMBER_FORM_SIGNUP_DATA: &str =
        "email=mulan4%40gmail.com&username=mulan4&password=Allana%24n09878";
    const MEMBER_FORM_SIGNIN_DATA: &str = "email=mulan4%40gmail.com&&password=Allana%24n09878";

    #[tokio::test]
    async fn test_full_auth_org_flow() {
        clear_data().await;
        test_sign_up_admin().await;
        test_sign_in_admin().await;
        test_sign_up_member().await;
        test_sign_in_member().await;
        test_create_organization().await;
        test_read_organization_with_slug().await;
        test_read_organization_with_id().await;
        test_read_user_organizations().await;
        test_patch_organization().await;
        //  test_delete_organization().await;
        test_member_view_org_id_without_permission().await;
        test_create_organization_membership().await;
        test_member_view_org_id_with_permission().await;
        test_member_read_user_organizations().await;
        test_owner_update_organization_membership().await;
    }

    async fn test_sign_up_admin() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SIGN_UP_URI)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(ADMIN_FORM_SIGNUP_DATA))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    async fn test_sign_in_admin() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SIGN_IN_URI)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(ADMIN_FORM_SIGNIN_DATA))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: SignInFormResponse = serde_json::from_slice(&body_bytes).unwrap();
        *JWT_TOKEN_1.lock().unwrap() = Some(format!("Bearer {}", body.access_token));
        assert_eq!(body.token_type, "Bearer");
    }

    async fn test_sign_up_member() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SIGN_UP_URI)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(MEMBER_FORM_SIGNUP_DATA))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    async fn test_sign_in_member() {
        let state = AppState::init().await.unwrap();
        let app = app(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SIGN_IN_URI)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(MEMBER_FORM_SIGNIN_DATA))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: SignInFormResponse = serde_json::from_slice(&body_bytes).unwrap();
        *JWT_TOKEN_2.lock().unwrap() = Some(format!("Bearer {}", body.access_token));
        assert_eq!(body.token_type, "Bearer");
    }

    async fn test_create_organization() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/organizations")
                    .header(AUTHORIZATION, JWT_TOKEN_1.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&CreateOrgRequest {
                            name: "my very new organization".to_string(),
                            description: "the very create description which wont be small at all"
                                .to_string(),
                            logo_url: None,
                            website_url: None,
                            metadata: None,
                            settings: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, body) = response.into_parts();

        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let a = String::from_utf8_lossy(&body_bytes).to_string();
        let a: Organization = serde_json::from_str(&a).unwrap();

        *ORG_ID.lock().unwrap() = Some(a.id);
        assert_eq!(parts.status, StatusCode::CREATED);
    }

    async fn test_read_organization_with_slug() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/auth/organizations/{}",
                        "my-very-new-organization"
                    ))
                    .header(AUTHORIZATION, JWT_TOKEN_1.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, body) = response.into_parts();

        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let a = String::from_utf8_lossy(&body_bytes).to_string();
        let a: Organization = serde_json::from_str(&a).unwrap();

        assert_eq!(a.name, "my very new organization");
        assert_eq!(parts.status, StatusCode::OK);
    }

    async fn test_read_organization_with_id() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/auth/organizations/{}",
                        ORG_ID.lock().unwrap().clone().unwrap()
                    ))
                    .header(AUTHORIZATION, JWT_TOKEN_1.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, body) = response.into_parts();

        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let a = String::from_utf8_lossy(&body_bytes).to_string();
        let a: Organization = serde_json::from_str(&a).unwrap();

        assert_eq!(a.name, "my very new organization");
        assert_eq!(parts.status, StatusCode::OK);
    }

    async fn test_read_user_organizations() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/auth/organizations")
                    .header(AUTHORIZATION, JWT_TOKEN_1.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, body) = response.into_parts();

        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let a = String::from_utf8_lossy(&body_bytes).to_string();
        let a: Vec<Organization> = serde_json::from_str(&a).unwrap();

        assert_eq!(a.len(), 1);
        assert_eq!(parts.status, StatusCode::OK);
    }

    async fn test_patch_organization() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!(
                        "/auth/organizations/{}",
                        ORG_ID.lock().unwrap().clone().unwrap()
                    ))
                    .header(AUTHORIZATION, JWT_TOKEN_1.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"name":"the org became old news"}))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, body) = response.into_parts();

        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let a = String::from_utf8_lossy(&body_bytes).to_string();
        let a: Organization = serde_json::from_str(&a).unwrap();

        assert_eq!(a.name, "the org became old news");
        assert_eq!(parts.status, StatusCode::CREATED);
    }

    async fn _test_delete_organization() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/auth/organizations/{}",
                        ORG_ID.lock().unwrap().clone().unwrap()
                    ))
                    .header(AUTHORIZATION, JWT_TOKEN_1.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, body) = response.into_parts();

        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let a = String::from_utf8_lossy(&body_bytes).to_string();

        assert_eq!(a, "organization deleted successfully");
        assert_eq!(parts.status, StatusCode::OK);
    }

    async fn test_member_view_org_id_without_permission() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/auth/organizations/{}",
                        ORG_ID.lock().unwrap().clone().unwrap()
                    ))
                    .header(AUTHORIZATION, JWT_TOKEN_2.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, _body) = response.into_parts();

        // let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        // let a = String::from_utf8_lossy(&body_bytes).to_string();
        // let a: Organization = serde_json::from_str(&a).unwrap();

        // assert_eq!(a.name, "my very new organization");
        assert_eq!(parts.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    async fn test_create_organization_membership() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/auth/organizations/{}/memberships",
                        ORG_ID.lock().unwrap().clone().unwrap()
                    ))
                    .header(AUTHORIZATION, JWT_TOKEN_1.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&CreateOrganizationMembership2 {
                            email: "mulan4@gmail.com".to_string(),
                            custom_permissions: None,
                            metadata: None,
                            role: "Viewer".to_string(),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let a = String::from_utf8_lossy(&body_bytes).to_string();
        let a: OrganizationMembership = serde_json::from_str(&a).unwrap();

        *MEMBER_ID.lock().unwrap() = Some(a.id);
        assert_eq!(parts.status, StatusCode::CREATED);
    }

    async fn test_member_view_org_id_with_permission() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/auth/organizations/{}",
                        ORG_ID.lock().unwrap().clone().unwrap()
                    ))
                    .header(AUTHORIZATION, JWT_TOKEN_2.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, _body) = response.into_parts();

        // let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        // let a = String::from_utf8_lossy(&body_bytes).to_string();
        // let a: Organization = serde_json::from_str(&a).unwrap();

        // assert_eq!(a.name, "my very new organization");
        assert_eq!(parts.status, StatusCode::OK);
    }

    async fn test_member_read_user_organizations() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/auth/organizations")
                    .header(AUTHORIZATION, JWT_TOKEN_2.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, body) = response.into_parts();

        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let a = String::from_utf8_lossy(&body_bytes).to_string();
        let a: Vec<Organization> = serde_json::from_str(&a).unwrap();

        assert_eq!(a.len(), 1);
        assert_eq!(parts.status, StatusCode::OK);
    }

    async fn test_owner_update_organization_membership() {
        let state = AppState::init().await.unwrap();
        let app = app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!(
                        "/auth/organizations/{}/memberships/{}",
                        ORG_ID.lock().unwrap().clone().unwrap(),
                        MEMBER_ID.lock().unwrap().clone().unwrap(),
                    ))
                    .header(AUTHORIZATION, JWT_TOKEN_1.lock().unwrap().clone().unwrap())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"custom_permissions":["TeamsDelete"]})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, _body) = response.into_parts();

        assert_eq!(parts.status, StatusCode::CREATED);
    }
    async fn clear_data() {
        #[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
        pub struct Record {
            pub id: surrealdb::RecordId,
        }
        let tables = [
            USER_TABLE,
            AUTH_PASSWORD_TABLE,
            ORGANIZATION_TABLE,
            ORGANIZATION_MEMBERSHIP_TABLE,
            ROLE_TABLE,
        ];
        let state = AppState::init().await.unwrap();
        for table in tables {
            let _: Vec<Record> = state.sdb.delete(table).await.unwrap();
        }
    }
}
