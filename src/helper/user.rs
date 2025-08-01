// use surrealdb::{RecordId, Surreal, engine::remote::ws::Client};

// use crate::errors::{Error, Result};
// use crate::{consts::auth_const::USER_TABLE, models::user::User};

// pub async fn get_user_with_email(
//     sdb: Surreal<Client>,
//     email: String,
//     id: RecordId,
// ) -> Result<User> {
//     let get_user: Vec<User> = sdb
//         .query("SELECT * FROM type::table($table) WHERE email = $email AND id = $id;")
//         .bind(("table", USER_TABLE))
//         .bind(("email", email))
//         .bind(("id", id))
//         .await?
//         .take(0)?;

//     let a = get_user.first().ok_or(Error::EmailNotExist(())).map(|q| q.clone());

//     todo!()
// }
