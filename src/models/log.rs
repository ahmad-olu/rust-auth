use surrealdb::RecordId;

pub struct Invitation {
    pub id: RecordId,
    pub organization_id: Option<RecordId>,
    pub user_id: Option<RecordId>,

    // ? Event details
    pub action: String,        // ! (len 100)
    pub resource_type: String, // ! (len 50)
    pub resource_id: Option<RecordId>,

    // ? Context
    pub id_address: Option<String>,
    pub user_agent: Option<RecordId>,
    pub metadata: Option<serde_json::Value>,

    pub created_at: String,
}
