use axum::{routing::post, Router, Json};
use serde::Deserialize;

#[derive(Deserialize)]
struct Item {
    name: String,
}

async fn create_item(Json(_): Json<Item>) {
    // No auth extractor — anyone can POST.
}

fn helper(label: &str) -> String {
    format!("[{}]", label)
}

pub fn router() -> Router {
    Router::new()
        .route("/items", post(create_item))
}
