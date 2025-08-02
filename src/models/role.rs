use std::{collections::HashSet, fmt::Debug};

use crate::{
    consts::auth_const::ROLE_TABLE, errors::Result, models::permission::Permission,
    utils::time::time_now,
};
use serde::{Deserialize, Serialize};
use surrealdb::{RecordId, Surreal, engine::remote::ws::Client};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum PRoles {
    Owner,
    Admin,
    Member,
    Viewer,
}
// impl Debug for PRoles {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             Self::Owner => write!(f, "Owner"),
//             Self::Admin => write!(f, "Admin"),
//             Self::Member => write!(f, "Member"),
//             Self::Viewer => write!(f, "Viewer"),
//         }
//     }
// }

pub fn contains_default_role(val: &str) -> bool {
    ["Owner", "Admin", "Member", "Viewer"].contains(&val)
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Roles {
    pub id: RecordId,
    pub organization_id: RecordId,
    pub name: String, // ! & (len = 100)
    pub key: String,  // ! 'admin', 'member', 'viewer' & (len = 100)
    pub description: Option<String>,
    pub permissions: HashSet<Permission>, // !  (default []),
    pub is_default: bool,                 // ! (default false)
    pub is_system: bool,
    pub created_at: String,
    pub updated_at: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub deleted_at: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CreateRoles {
    pub organization_id: RecordId,
    pub name: String, // ! & (len = 100)
    pub key: String,  // ! 'admin', 'member', 'viewer' & (len = 100)
    pub description: Option<String>,
    pub permissions: HashSet<Permission>, // !  (default []),
    pub is_default: bool,                 // ! (default false)
    pub is_system: bool,
    pub created_at: String,
    pub metadata: Option<serde_json::Value>,
}

pub async fn inti_roles(sdb: &Surreal<Client>, organization_id: RecordId) -> Result<()> {
    let default_roles = vec![
        CreateRoles {
            organization_id: organization_id.clone(),
            name: "Owner".to_string(),
            key: "owner".to_string(),
            description: Some("Full organization access".to_string()),
            permissions: HashSet::from([Permission::All]),
            is_default: true,
            is_system: true,
            created_at: time_now(),
            metadata: None,
        },
        CreateRoles {
            organization_id: organization_id.clone(),
            name: "Admin".to_string(),
            key: "admin".to_string(),
            description: Some("Administrative access".to_string()),
            permissions: HashSet::from([
                Permission::OrgRead,
                Permission::OrgUpdate,
                Permission::MembersRead,
                Permission::MembersInvite,
                Permission::MembersUpdate,
                Permission::MembersRemove,
                Permission::TeamsCreate,
                Permission::TeamsRead,
                Permission::TeamsUpdate,
                Permission::TeamsDelete,
                Permission::RolesRead,
                Permission::RolesAssign,
            ]),
            is_default: true,
            is_system: true,
            created_at: time_now(),
            metadata: None,
        },
        CreateRoles {
            organization_id: organization_id.clone(),
            name: "Member".to_string(),
            key: "member".to_string(),
            description: Some("Standard member access".to_string()),
            permissions: HashSet::from([
                Permission::OrgRead,
                Permission::MembersRead,
                Permission::TeamsRead,
                Permission::TeamsJoin,
            ]),
            is_default: true,
            is_system: true,
            created_at: time_now(),
            metadata: None,
        },
        CreateRoles {
            organization_id: organization_id,
            name: "Viewer".to_string(),
            key: "viewer".to_string(),
            description: Some("Read-only access".to_string()),
            permissions: HashSet::from([
                Permission::OrgRead,
                Permission::MembersRead,
                Permission::TeamsRead,
            ]),
            is_default: true,
            is_system: true,
            created_at: time_now(),
            metadata: None,
        },
    ];
    for r in default_roles {
        let _: Option<Roles> = sdb.create(ROLE_TABLE).content(r).await?;
    }
    Ok(())
}
