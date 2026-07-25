use axum::{routing::post, Router, Json};
use serde::Deserialize;

#[derive(Deserialize)]
struct Item {
    name: String,
}

async fn create_item(Json(_): Json<Item>) {
    // No auth extractor — anyone can POST.
}

struct AuthContext;

async fn update_item(AuthContext: AuthContext, Json(_): Json<Item>) {
    // The safe twin carries an explicit authentication context.
}

fn helper(label: &str) -> String {
    format!("[{}]", label)
}

pub fn router() -> Router {
    Router::new()
        .route("/items", post(create_item))
        .route("/items/:id", post(update_item))
}
