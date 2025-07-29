use surrealdb::RecordId;

pub struct Roles {
    pub id: RecordId,
    pub organization_id: RecordId,
    pub name: String, // ! & (len = 100)
    pub key: String,  // ! 'admin', 'member', 'viewer' & (len = 100)
    pub description: String,
    pub permissions: Vec<String>, // !  (default []),
    pub is_default: Option<bool>, // ! (default false)
    pub created_at: String,
    pub updated_at: Option<String>,
    pub metadata: Option<serde_json::Value>,
}
