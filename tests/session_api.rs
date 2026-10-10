use authcore::{app, security, state::AppState};
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
    body: Option<Value>,
    bearer: Option<&str>,
) -> Response<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let mut request = request
        .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:35112".parse::<SocketAddr>().unwrap(),
    ));
    router.clone().oneshot(request).await.unwrap()
}

async fn read_json(response: Response<Body>) -> Value {
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn sessions_are_user_scoped_and_global_logout_revokes_every_device() {
    if std::env::var("DATABASE_URL").is_err() {
        return;
    }

    let state = AppState::from_env().await.expect("test services required");
    let api = app(state);
    let password = security::generate_refresh().0;
    let email = format!("sessions-{}@example.com", Uuid::new_v4());
    let credentials = json!({ "email": email, "password": password });

    let register = call(
        &api,
        "POST",
        "/api/v1/auth/register",
        Some(credentials.clone()),
        None,
    )
    .await;
    assert_eq!(register.status(), StatusCode::CREATED);

    let login_a = call(
        &api,
        "POST",
        "/api/v1/auth/login",
        Some(credentials.clone()),
        None,
    )
    .await;
    assert_eq!(login_a.status(), StatusCode::OK);
    let token_a = read_json(login_a).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let login_b = call(&api, "POST", "/api/v1/auth/login", Some(credentials), None).await;
    assert_eq!(login_b.status(), StatusCode::OK);
    let token_b = read_json(login_b).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let list = call(&api, "GET", "/api/v1/auth/sessions", None, Some(&token_a)).await;
    assert_eq!(list.status(), StatusCode::OK);
    let sessions = read_json(list).await;
    let items = sessions["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let current_id = items.iter().find(|v| v["current"] == true).unwrap()["id"]
        .as_str()
        .unwrap();
    let other_id = items.iter().find(|v| v["current"] == false).unwrap()["id"]
        .as_str()
        .unwrap();
    assert_ne!(current_id, other_id);

    // Revoking one session does not affect the current session.
    let revoked = call(
        &api,
        "DELETE",
        &format!("/api/v1/auth/sessions/{other_id}"),
        None,
        Some(&token_a),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    let denied = call(&api, "GET", "/api/v1/auth/me", None, Some(&token_b)).await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let alive = call(&api, "GET", "/api/v1/auth/me", None, Some(&token_a)).await;
    assert_eq!(alive.status(), StatusCode::OK);

    let result = call(
        &api,
        "POST",
        "/api/v1/auth/logout-all",
        None,
        Some(&token_a),
    )
    .await;
    assert_eq!(result.status(), StatusCode::NO_CONTENT);
    let revoked = call(&api, "GET", "/api/v1/auth/me", None, Some(&token_a)).await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
}
