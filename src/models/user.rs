use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::json;
use surrealdb::RecordId;

// #[derive(serde::Deserialize, Debug, Clone, Serialize)]
// pub struct UserReq {
//     pub username: String,
//     pub email: String,
//     pub password_hash: String, // ! & (len = 255)
//     pub auth_provider: Option<AuthProvider>,
//     pub created_at: String,
//     pub mfa: Option<bool>,
//     pub email_verified: bool,
// }

// #[derive(serde::Deserialize, Debug, Clone, Serialize)]
// pub struct UserRes {
//     id: RecordId,
//     pub username: String,
//     pub email: String,
//     pub created_at: String,
//     pub mfa: Option<bool>,
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuthProvider {
    Classic, //Email and Password
    PasswordLess,
    MagicLink,
    Amazon,
    Discord,
    Github,
    Facebook,
    Google,
    Linkedin,
    Stripe,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum UserStatus {
    Active,
    Suspended,
    InActive,
}

pub struct UserWithPassword {
    pub id: RecordId,
    pub user_id: RecordId,
    pub password_hash: String, // ! & (len = 255)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub id: RecordId,
    pub user_name: Option<String>,
    pub first_name: Option<String>, // ! & (len = 100)
    pub last_name: Option<String>,  // ! & (len = 100)
    pub email: String,              // ! unique & (len = 255)
    pub phone: Option<String>,      // ! & (len = 20)
    pub image_url: Option<String>,
    pub email_verified: Option<bool>,
    pub phone_verified: Option<bool>,
    pub two_factor_enabled: Option<bool>, //Multi factor authentication status.
    pub backup_codes_generated_at: Option<String>, // ! TIMESTAMP
    pub auth_provider: Option<AuthProvider>,
    pub created_at: String,
    pub updated_at: Option<String>,
    pub local: Option<String>, // ! e.g `ng`
    pub blocked: Option<bool>,
    pub status: UserStatus,
    pub reason_for_block: Option<String>,
    pub deleted_at: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

// ! break the user table into smaller table

pub struct UserCreate {
    pub user: HashMap<String, serde_json::Value>,
}

impl UserCreate {
    pub fn username(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("user_name".into(), json!(val));
        }
        self
    }
    pub fn first_name(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("first_name".into(), json!(val));
        }
        self
    }
    pub fn last_name(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("last_name".into(), json!(val));
        }
        self
    }
    pub fn email(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("email".into(), json!(val));
        }
        self
    }
    pub fn phone(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("phone".into(), json!(val));
        }
        self
    }
    pub fn image_url(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("image_url".into(), json!(val));
        }
        self
    }
    pub fn email_verified(&mut self, val: bool) -> &UserCreate {
        self.user.insert("email_verified".into(), json!(val));
        self
    }
    pub fn phone_verified(&mut self, val: bool) -> &UserCreate {
        self.user.insert("phone_verified".into(), json!(val));
        self
    }
    pub fn mfa(&mut self, val: bool) -> &UserCreate {
        self.user.insert("mfa".into(), json!(val));
        self
    }
    pub fn local(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("local".into(), json!(val));
        }
        self
    }
    pub fn blocked(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("blocked".into(), json!(val));
        }
        self
    }
    pub fn updated_at(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("updated_at".into(), json!(val));
        }
        self
    }
    pub fn status(&mut self, val: UserStatus) -> &UserCreate {
        self.user.insert("status".into(), json!(val));
        self
    }

    pub fn reason_for_block(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("reason_for_block".into(), json!(val));
        }
        self
    }
    pub fn deleted_at(&mut self, val: &str) -> &UserCreate {
        if val.len() != 0 {
            self.user.insert("deleted_at".into(), json!(val));
        }
        self
    }

    pub fn build(&self) -> serde_json::Value {
        return serde_json::json!(self.user);
    }
}
