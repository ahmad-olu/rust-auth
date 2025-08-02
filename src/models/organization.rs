// use chrono::{DateTime, Local};

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

use crate::models::permission::Permission;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub enum OrganizationMembershipStatus {
    Active,
    InActive,
    Pending,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Organization {
    pub id: RecordId,
    pub name: String, // ! & (len = 255)
    pub slug: String, // ! (unique) & (length should be less than 100 char) & (len = 100)
    pub description: String,
    pub blocked: bool, // ! false
    pub reason_for_block: Option<String>,
    pub logo_url: Option<String>,
    pub website_url: Option<String>,

    // ? settings
    pub settings: Option<serde_json::Value>,

    // ? metadata
    pub metadata: Option<serde_json::Value>,
    pub created_by: RecordId,
    pub created_at: String,
    pub updated_at: Option<String>,
    pub deleted_at: Option<String>, // ! timestamp
}

#[derive(Serialize, Debug, Clone)]
pub struct CreateOrganization {
    pub name: String, // ! & (len = 255)
    pub slug: String, // ! (unique) & (length should be less than 100 char) & (len = 100)
    pub description: String,
    pub blocked: bool, // ! false
    pub logo_url: Option<String>,
    pub website_url: Option<String>,
    pub settings: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub created_by: RecordId,
    pub created_at: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OrganizationMembership {
    pub id: RecordId,
    pub user_id: RecordId,
    pub organization_id: RecordId,
    pub role: String,                         // ! (default member) & (less than 50)
    pub status: OrganizationMembershipStatus, // ! (default active)

    pub custom_permissions: Option<HashSet<Permission>>, // !  Permissions (can override role permissions)

    // ? metadata
    pub metadata: Option<serde_json::Value>,
    pub joined_at: Option<String>,
    pub invited_by: Option<RecordId>,
    pub created_at: String,
    pub updated_at: Option<String>,
    pub deleted_at: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct CreateOrganizationMembership {
    pub user_id: RecordId,
    pub organization_id: RecordId,
    pub role: String,                         // ! (default member) & (less than 50)
    pub status: OrganizationMembershipStatus, // ! (default active)

    // ? metadata
    pub custom_permissions: Option<HashSet<Permission>>, // !  Permissions (can override role permissions)
    pub metadata: Option<serde_json::Value>,
    pub joined_at: Option<String>,
    pub invited_by: Option<RecordId>,
    pub created_at: String,
}
