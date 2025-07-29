// use chrono::{DateTime, Local};

use surrealdb::RecordId;

pub enum OrganizationStatus {
    Active,
    InActive,
    Pending,
}

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

pub struct OrganizationMembership {
    pub id: RecordId,
    pub user_id: RecordId,
    pub organization_id: RecordId,
    pub role: String,               // ! (default member) & (less than 50)
    pub status: OrganizationStatus, // ! (default active)

    pub custom_permissions: Vec<String>, // !  Permissions (can override role permissions)

    // ? metadata
    pub metadata: Option<serde_json::Value>,
    pub joined_at: String,
    pub invited_by: RecordId,
    pub created_at: String,
    pub updated_at: Option<String>,
}
