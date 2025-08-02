use surrealdb::{RecordId, Surreal, engine::remote::ws::Client};

use crate::consts::auth_const::{ORGANIZATION_MEMBERSHIP_TABLE, ROLE_TABLE};
use crate::models::organization::{
    Organization, OrganizationMembership, OrganizationMembershipStatus,
};
use crate::models::permission::PermissionContext;

use crate::errors::{Error, Result};
use crate::models::role::Roles;
use crate::models::user::User;

pub async fn create_context(
    sdb: &Surreal<Client>,
    user_id: RecordId,
    org_id: RecordId,
) -> Result<PermissionContext> {
    let user: User = sdb
        .select(user_id.clone())
        .await?
        .ok_or(Error::InternalServerError)?;
    // println!("1. =========> {:?}", user.id);
    // TODO: Check for deleted_at
    let organization: Organization = sdb
        .select(org_id.clone())
        .await?
        .ok_or(Error::InternalServerError)?;
    // println!("2. =========> {:?}", organization.id);
    let membership: OrganizationMembership = sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND user_id = $user_id AND status = $status;")
        .bind(("table", ORGANIZATION_MEMBERSHIP_TABLE))
        .bind(("organization_id", org_id.clone()))
        .bind(("user_id", user_id))
        .bind(("status", OrganizationMembershipStatus::Active))
        .await?
        .take::<Vec<OrganizationMembership>>(0)?
        .into_iter()
        .next()
        .ok_or(Error::InternalServerError)?;
    // println!("3. =========> {:?}", membership.id);
    // TODO: Get team membership

    let mem_role = membership.clone();
    let role: Roles = sdb
        .query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND name = $name;")
    //.query("SELECT * FROM type::table($table) WHERE organization_id = $organization_id AND name = $name AND permissions CONTAINSANY $permissions;")
        .bind(("table", ROLE_TABLE))
        .bind(("organization_id", org_id))
        .bind(("name", mem_role.role.clone()))
        //.bind(("permissions", mem_role.custom_permissions.clone()))
        .await?
        .take::<Vec<Roles>>(0)?
        .into_iter()
        .next()
        .ok_or(Error::InternalServerError)?;
    // println!("4. =========> {:?}", role.permissions);
    Ok(PermissionContext {
        user,
        organization,
        organization_membership: membership,
        organization_role: role.clone(),
        team_memberships: Vec::new(),
        effective_permissions: role.permissions,
    })
}
