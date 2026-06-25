//! Deliberately vulnerable axum + sqlx fixture for Plan F multilang coverage tests.
//!
//! Route `/users` extracts a user-controlled `name` from `axum::extract::Query`
//! and builds a raw SQL string that is passed directly to `sqlx::query`.
//! This is an intentional CWE-89 (SQL injection) sink reachable from an HTTP
//! source — clippy / semgrep / static_hunter should flag the dataflow.

use axum::{extract::Query, routing::get, Router};
use serde::Deserialize;
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::net::SocketAddr;

#[derive(Debug, Deserialize)]
struct UserQuery {
    name: String,
}

async fn list_users(
    Query(q): Query<UserQuery>,
    pool: SqlitePool,
) -> String {
    // DELIBERATE SQLi SINK (CWE-89): user-controlled `q.name` is concatenated
    // directly into a raw SQL string and passed to sqlx::query.
    let sql = format!("SELECT id, name FROM users WHERE name = '{}'", q.name);
    let rows = sqlx::query(&sql).fetch_all(&pool).await.unwrap_or_default();
    rows.iter()
        .filter_map(|r| r.try_get::<String, _>("name").ok())
        .collect::<Vec<_>>()
        .join(",")
}

#[tokio::main]
async fn main() {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("pool");
    let pool_for_handler = pool.clone();
    let app = Router::new().route(
        "/users",
        get(move |q: Query<UserQuery>| {
            let pool = pool_for_handler.clone();
            async move { list_users(q, pool).await }
        }),
    );
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
