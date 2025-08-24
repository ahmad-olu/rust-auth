use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Declined,
    Expired,
    Cancelled,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Invitation {
    pub id: RecordId,
    pub team_id: Option<RecordId>,
    pub organization_id: Option<RecordId>,
    pub email: String, // ! & (len = 255)
    pub role: String,  // ! (default member) & (len = 50)

    // ? Invitation details
    pub token: String, // ! unique & (len = 255)
    pub invite_by: RecordId,
    pub message: Option<String>,

    // ? Status & Timing
    pub status: InvitationStatus,
    pub expires_at: String, // ! (now + 3 days)
    pub accepted_at: Option<String>,
    pub accepted_by: Option<RecordId>, // ! userId

    pub metadata: Option<serde_json::Value>,

    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CreateInvitation {
    pub team_id: Option<RecordId>,
    pub organization_id: Option<RecordId>,
    pub email: String, // ! & (len = 255)
    pub role: String,  // ! (default member) & (len = 50)

    // ? Invitation details
    pub token: String, // ! unique & (len = 255)
    pub invite_by: RecordId,
    pub message: Option<String>,

    // ? Status & Timing
    pub status: InvitationStatus,
    pub expires_at: String, // ! (now + 3 days)

    pub metadata: Option<serde_json::Value>,

    pub created_at: String,
}
