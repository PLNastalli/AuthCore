use authcore::{app, security, state::AppState};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
};
use serde_json::json;
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

async fn send(api: &axum::Router, path: &str, body: serde_json::Value) -> StatusCode {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:30120".parse::<SocketAddr>().unwrap(),
    ));
    api.clone().oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn pending_identity_cannot_login_before_single_use_confirmation() {
    if std::env::var("DATABASE_URL").is_err() {
        return;
    }
    let state = AppState::from_env()
        .await
        .expect("PostgreSQL and Redis required");
    let api = app(state.clone());
    let id = Uuid::new_v4();
    let email = format!("verify-{}@example.com", Uuid::new_v4());
    let password = "verify-email-strong-password-2026";
    let encoded = state.passwords.hash(password.to_owned()).await.unwrap();

    // An unverified account deliberately created as pending in a real database.
    sqlx::query("INSERT INTO users (id,email,password_hash) VALUES ($1,$2,$3)")
        .bind(id)
        .bind(&email)
        .bind(encoded)
        .execute(&state.db)
        .await
        .unwrap();
    let credentials = json!({"email":email,"password":password});
    assert_eq!(
        send(&api, "/api/v1/auth/login", credentials.clone()).await,
        StatusCode::UNAUTHORIZED
    );

    let (token, hash) = security::generate_refresh();
    sqlx::query(
        "INSERT INTO email_verification_tokens (id,user_id,token_hash,expires_at)
                 VALUES ($1,$2,$3,NOW()+INTERVAL '30 minutes')",
    )
    .bind(Uuid::new_v4())
    .bind(id)
    .bind(hash)
    .execute(&state.db)
    .await
    .unwrap();

    let payload = json!({"token":token});
    assert_eq!(
        send(&api, "/api/v1/auth/verify-email", payload.clone()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(&api, "/api/v1/auth/verify-email", payload).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&api, "/api/v1/auth/login", credentials).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn simultaneous_different_email_tokens_do_not_deadlock_or_both_succeed() {
    if std::env::var("DATABASE_URL").is_err() {
        return;
    }
    let state = AppState::from_env().await.expect("test infrastructure required");
    let api = app(state.clone());
    let id = Uuid::new_v4();
    let email = format!("parallel-verify-{}@example.com", Uuid::new_v4());
    let password = state.passwords.hash("parallel-verify-password-2026".into()).await.unwrap();
    sqlx::query("INSERT INTO users (id,email,password_hash) VALUES ($1,$2,$3)")
        .bind(id).bind(&email).bind(password).execute(&state.db).await.unwrap();

    let (first, first_hash) = security::generate_refresh();
    let (second, second_hash) = security::generate_refresh();
    for digest in [first_hash, second_hash] {
        sqlx::query("INSERT INTO email_verification_tokens (id,user_id,token_hash,expires_at)
                     VALUES ($1,$2,$3,NOW()+INTERVAL '30 minutes')")
            .bind(Uuid::new_v4()).bind(id).bind(digest).execute(&state.db).await.unwrap();
    }
    let (first_status, second_status) = tokio::join!(
        send(&api,"/api/v1/auth/verify-email",json!({"token":first})),
        send(&api,"/api/v1/auth/verify-email",json!({"token":second})),
    );
    let statuses = [first_status, second_status];
    assert_eq!(statuses.iter().filter(|&&s| s == StatusCode::NO_CONTENT).count(), 1);
    assert_eq!(statuses.iter().filter(|&&s| s == StatusCode::UNAUTHORIZED).count(), 1);
}
