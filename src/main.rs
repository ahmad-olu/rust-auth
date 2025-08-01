use axum::Router;
use tracing::info;
use tracing_subscriber::FmtSubscriber;

use crate::{errors::Result, routes::auth_route::auth_router, state::AppState};

pub mod consts;
pub mod errors;
pub mod helper;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod state;
pub mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    tracing::subscriber::set_global_default(FmtSubscriber::default()).unwrap();
    let state = AppState::init().await?;

    const PORT: &str = "3587";

    info!("Starting server");

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", PORT)).await?;
    info!("Serving auth at http://{}", listener.local_addr()?);
    axum::serve(listener, app(state)).await?;

    Ok(())
}

pub fn app(state: AppState) -> Router {
    Router::new()
        //.route("/", get(root_route))
        .nest("/auth", auth_router(state.clone()))
        .with_state(state)
}
