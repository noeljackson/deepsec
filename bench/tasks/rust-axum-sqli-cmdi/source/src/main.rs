use axum::{extract::Query, routing::get, Router};
use serde::Deserialize;
use sqlx::PgPool;
use std::process::Command;

#[derive(Deserialize)]
struct UserQuery {
    name: String,
    tool: String,
}

async fn lookup_vulnerable(Query(q): Query<UserQuery>, pool: PgPool) -> String {
    let row: (String,) = sqlx::query_as(&format!("SELECT email FROM users WHERE name = '{}'", q.name))
        .fetch_one(&pool)
        .await
        .unwrap();
    row.0
}

async fn lookup_safe(Query(q): Query<UserQuery>, pool: PgPool) -> String {
    let row: (String,) = sqlx::query_as("SELECT email FROM users WHERE name = $1")
        .bind(&q.name)
        .fetch_one(&pool)
        .await
        .unwrap();
    row.0
}

fn run_vulnerable(tool: &str) {
    let _ = Command::new(tool).status();
}

fn run_safe() {
    let _ = Command::new("ls").arg("-la").status();
}

pub fn router() -> Router {
    Router::new()
        .route("/lookup/vulnerable", get(lookup_vulnerable))
        .route("/lookup/safe", get(lookup_safe))
}
