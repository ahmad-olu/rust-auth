use surrealdb::{
    Surreal,
    engine::remote::ws::{Client, Ws},
    opt::auth::Root,
};

use crate::errors::Result;

#[derive(Debug, Clone)]
pub struct AppState {
    pub sdb: Surreal<Client>,
}

impl AppState {
    pub async fn init() -> Result<Self> {
        let sdb = Surreal::new::<Ws>("localhost:8050").await?;
        sdb.signin(Root {
            username: "root",
            password: "secret",
        })
        .await?;
        sdb.use_ns("test").use_db("test").await?;

        Ok(Self { sdb })
    }
}
