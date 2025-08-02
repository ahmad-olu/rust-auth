use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PasswordResetTokens {
    pub id: RecordId,
    pub user_id: RecordId,
    pub token_hash: String,
    pub expire_at: String,
    pub used_at: String,
    pub ip_address: String,
    pub created_at: String,
}
