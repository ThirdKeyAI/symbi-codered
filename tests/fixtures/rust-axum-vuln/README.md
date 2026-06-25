# rust-axum-vuln

Deliberately vulnerable axum + sqlx fixture used by Plan F multilang
coverage tests. The `/users` handler in `src/main.rs` extracts a
user-controlled `name` from `axum::extract::Query` and concatenates it
directly into a raw SQL string passed to `sqlx::query` — this is an
intentional CWE-89 (SQL injection) sink and must NOT be used outside
this test fixture.
