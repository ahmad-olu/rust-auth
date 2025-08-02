use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

use crate::errors::{Error, Result};
use crate::models::{
    organization::{Organization, OrganizationMembership, OrganizationMembershipStatus},
    role::Roles,
    team::{Team, TeamMembership},
    user::User,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    OrgRead,
    OrgUpdate,
    OrgDelete,

    MembersRead,
    MembersInvite,
    MembersUpdate,
    MembersRemove,
    MembersRoles,

    TeamsCreate,
    TeamsRead,
    TeamsUpdate,
    TeamsDelete,
    TeamsJoin,
    TeamsLeave,

    RolesCreate,
    RolesRead,
    RolesUpdate,
    RolesDelete,
    RolesAssign,

    LogRead,
    LogExport,

    All,
}

#[derive(Debug, Clone)]
pub struct PermissionContext {
    pub user: User,
    pub organization: Organization,
    pub organization_membership: OrganizationMembership,
    pub organization_role: Roles,
    pub team_memberships: Vec<(Team, TeamMembership, Roles)>,
    pub effective_permissions: HashSet<Permission>,
}

pub trait PermissionChecker {
    fn has_permission(&self, permission: &Permission) -> bool;
    fn has_any_permission(&self, permissions: &[Permission]) -> bool;
    fn has_all_permissions(&self, permissions: &[Permission]) -> bool;
    fn can_access_organization(&self, org_id: &RecordId) -> bool;
    fn can_access_team(&self, team_id: &RecordId) -> bool;
    fn is_organization_owner(&self) -> bool;
    fn is_team_admin(&self, team_id: &RecordId) -> bool;

    fn check_permission(&self, permission: &Permission) -> Result<()>;
    fn validate_resource_access(
        &self,

        resource_type: &str,
        resource_id: &RecordId,
        action: &Permission,
    ) -> Result<()>;
}

impl PermissionChecker for PermissionContext {
    fn has_permission(&self, permission: &Permission) -> bool {
        self.effective_permissions.contains(permission)
            || self.effective_permissions.contains(&Permission::All)
    }

    fn has_any_permission(&self, permissions: &[Permission]) -> bool {
        if self.effective_permissions.contains(&Permission::All) {
            return true;
        }
        permissions
            .iter()
            .any(|p| self.effective_permissions.contains(p))
    }

    fn has_all_permissions(&self, permissions: &[Permission]) -> bool {
        if self.effective_permissions.contains(&Permission::All) {
            return true;
        }
        permissions
            .iter()
            .all(|p| self.effective_permissions.contains(p))
    }

    fn can_access_organization(&self, org_id: &RecordId) -> bool {
        &self.organization.id == org_id
            && self.organization_membership.status == OrganizationMembershipStatus::Active
    }

    fn can_access_team(&self, team_id: &RecordId) -> bool {
        self.team_memberships
            .iter()
            .any(|(team, membership, _)| &team.id == team_id && membership.user_id == self.user.id)
    }

    fn is_organization_owner(&self) -> bool {
        self.organization_role.key == "owner"
    }

    fn is_team_admin(&self, team_id: &RecordId) -> bool {
        self.team_memberships
            .iter()
            .any(|(team, membership, role)| {
                &team.id == team_id
                    && membership.user_id == self.user.id
                    && (role.key == "admin" || role.key == "owner")
            })
    }

    fn check_permission(&self, permission: &Permission) -> Result<()> {
        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(Error::AccessDenied(permission.clone()))
        }
    }

    fn validate_resource_access(
        &self,

        resource_type: &str,
        resource_id: &RecordId,
        action: &Permission,
    ) -> Result<()> {
        self.check_permission(action)?;

        match resource_type {
            "team" => {
                if !self.can_access_team(resource_id) {
                    return Err(Error::AccessDenied(action.clone()));
                }
            }
            "organization" => {
                if !self.can_access_organization(resource_id) {
                    return Err(Error::AccessDenied(action.clone()));
                }
            }
            _ => {}
        }

        Ok(())
    }
}
