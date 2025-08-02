use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

use crate::models::permission::Permission;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub enum TeamMembershipStatus {
    Active,
    InActive,
    Pending,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Team {
    pub id: RecordId,
    pub organization_id: RecordId,
    pub name: String, // ! & (len = 255)
    pub slug: String, // ! & (len = 100)
    pub description: String,

    // ? Hierarchy
    pub parent_team_id: RecordId, // !team id

    // ? Settings
    pub is_private: bool,                    // ! (default false)
    pub settings: Option<serde_json::Value>, // ! (default {})

    // ? Metadata
    pub metadata: Option<serde_json::Value>,
    pub created_by: RecordId,
    pub created_at: String,
    pub updated_at: Option<String>,
    pub deleted_at: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TeamMembership {
    pub id: RecordId,
    pub team_id: RecordId,
    pub organization_id: RecordId,
    pub user_id: RecordId,
    pub role: String, // ! (default member) & (less than 50)
    pub status: TeamMembershipStatus,

    // ? Permissions
    pub permissions: Option<HashSet<Permission>>,

    // ?  Metadata
    pub metadata: Option<serde_json::Value>,
    pub joined_at: String,
    pub added_by: RecordId,
    pub created_at: String,
    pub deleted_at: Option<String>,
}
