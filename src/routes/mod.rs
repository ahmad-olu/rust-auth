pub mod admin_panel;
pub mod auth_route;

pub async fn root_route() -> &'static str {
    "hello"
}
