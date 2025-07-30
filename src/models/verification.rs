use chrono::{DateTime, Duration, FixedOffset, Local};
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Deserialize, Debug, Clone)]
pub struct EmailVerification {
    pub id: RecordId,
    pub user_id: RecordId,
    pub token: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct CreateEmailVerification {
    pub user_id: RecordId,
    pub token: String,
    pub created_at: String,
    pub expires_at: String,
}

impl CreateEmailVerification {
    pub fn init(user_id: RecordId, token: String) -> Self {
        let expires_at = Local::now() + Duration::hours(1); // add 1 hour
        let expires_at: DateTime<FixedOffset> = expires_at.with_timezone(&expires_at.offset());
        let expires_at = expires_at.to_rfc3339();

        let created_at = Local::now() + Duration::hours(1); // add 1 hour
        let created_at: DateTime<FixedOffset> = created_at.with_timezone(&created_at.offset());
        let created_at = created_at.to_rfc3339();

        Self {
            user_id,
            token,
            created_at,
            expires_at,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct EmailChangeToken {
    pub id: RecordId,
    pub user_id: RecordId,
    pub email: String,
    pub token: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct CreateEmailChangeToken {
    pub user_id: RecordId,
    pub token: String,
    pub email: String,
    pub created_at: String,
    pub expires_at: String,
}

impl CreateEmailChangeToken {
    pub fn init(user_id: RecordId, email: String, token: String) -> Self {
        let expires_at = Local::now() + Duration::hours(1); // add 1 hour
        let expires_at: DateTime<FixedOffset> = expires_at.with_timezone(&expires_at.offset());
        let expires_at = expires_at.to_rfc3339();

        let created_at = Local::now() + Duration::hours(1); // add 1 hour
        let created_at: DateTime<FixedOffset> = created_at.with_timezone(&created_at.offset());
        let created_at = created_at.to_rfc3339();

        Self {
            user_id,
            email,
            token,
            created_at,
            expires_at,
        }
    }
}
