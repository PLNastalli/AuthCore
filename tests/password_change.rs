use authcore::{app, state::AppState};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, Response, StatusCode},
    Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

async fn call(
    router: &Router,
    method: &str,
    path: &str,
    value: Value,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut request = request.body(Body::from(value.to_string())).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.12:30420".parse::<SocketAddr>().unwrap(),
    ));
    router.clone().oneshot(request).await.unwrap()
}

#[tokio::test]
async fn parallel_password_changes_never_both_commit() {
    if std::env::var("DATABASE_URL").is_err() {
        return;
    }
    let state = AppState::from_env().await.expect("database required");
    let api = app(state);
    let email = format!("password-cas-{}@example.com", Uuid::new_v4());
    let old = "change-old-password-2026";
    let first_password = "first-password-candidate-2026";
    let second_password = "second-password-candidate-2026";
    let credentials = json!({"email":email, "password":old});

    let register = call(
        &api,
        "POST",
        "/api/v1/auth/register",
        credentials.clone(),
        &[],
    )
    .await;
    assert_eq!(register.status(), StatusCode::CREATED);
    let response = call(&api, "POST", "/api/v1/auth/login", credentials.clone(), &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    let bearer = format!("Bearer {}", json["access_token"].as_str().unwrap());
    let authorization = [("authorization", bearer.as_str())];

    let (first, second) = tokio::join!(
        call(
            &api,
            "POST",
            "/api/v1/auth/change-password",
            json!({"current_password":old,"new_password":first_password}),
            &authorization
        ),
        call(
            &api,
            "POST",
            "/api/v1/auth/change-password",
            json!({"current_password":old,"new_password":second_password}),
            &authorization
        ),
    );
    let statuses = [first.status(), second.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|&&s| s == StatusCode::NO_CONTENT)
            .count(),
        1,
        "exactly one credential update must succeed: {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|&&s| s == StatusCode::UNAUTHORIZED)
            .count(),
        1
    );

    let old_login = call(&api, "POST", "/api/v1/auth/login", credentials, &[]).await;
    assert_eq!(old_login.status(), StatusCode::UNAUTHORIZED);
    let first_login = call(
        &api,
        "POST",
        "/api/v1/auth/login",
        json!({"email":email,"password":first_password}),
        &[],
    )
    .await;
    let second_login = call(
        &api,
        "POST",
        "/api/v1/auth/login",
        json!({"email":email,"password":second_password}),
        &[],
    )
    .await;
    let successful = [first_login.status(), second_login.status()];
    assert_eq!(
        successful.iter().filter(|&&s| s == StatusCode::OK).count(),
        1
    );
}
