use authcore::{app, security, state::{AppState, RecoveryMailer}};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{header, Request, Response, StatusCode},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tower::ServiceExt;
use uuid::Uuid;

async fn accept_email(
    State(sender): State<mpsc::UnboundedSender<String>>,
    Json(payload): Json<Value>,
) -> StatusCode {
    let body = payload["text"].as_str().expect("mailer must send email text");
    sender.send(body.to_owned()).expect("mailbox is open");
    StatusCode::OK
}

async fn call(
    api: &Router,
    route: &str,
    payload: Value,
    bearer: Option<&str>,
) -> Response<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(route)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let mut request = request.body(Body::from(payload.to_string())).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:43592".parse::<SocketAddr>().unwrap(),
    ));
    api.clone().oneshot(request).await.unwrap()
}

fn token_from_email(body: &str) -> String {
    body.lines()
        .map(str::trim)
        .find(|line| {
            line.len() == 64
                && line.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        .expect("one-time token missing from mock email")
        .to_owned()
}

async fn get_mail(receiver: &mut mpsc::UnboundedReceiver<String>) -> String {
    tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("mailer request timed out")
        .expect("mailer never sent a message")
}

#[tokio::test]
async fn local_mail_provider_proves_registration_and_recovery_end_to_end() {
    if std::env::var("DATABASE_URL").is_err() { return; }
    let (sender, mut receiver) = mpsc::unbounded_channel::<String>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let provider = Router::new()
        .route("/emails", post(accept_email))
        .with_state(sender);
    let provider_task = tokio::spawn(async move {
        axum::serve(listener, provider).await.unwrap();
    });

    let mut state = AppState::from_env().await.expect("integration services required");
    // Exercise the real verified-email path, not the debug-only CI bypass.
    state.dev_skip_email_verification = false;
    state.recovery_mailer = Some(Arc::new(RecoveryMailer {
        api_key: security::generate_refresh().0,
        from_email: "noreply@example.invalid".into(),
        api_endpoint: format!("http://127.0.0.1:{port}/emails"),
    }));
    let api = app(state);
    let email = format!("mail-provider-{}@example.com", Uuid::new_v4());
    let old_password = security::generate_refresh().0;
    let new_password = security::generate_refresh().0;
    let credentials = json!({"email":email,"password":old_password});

    let registered = call(&api, "/api/v1/auth/register", credentials.clone(), None).await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    // A pending account cannot sign in before the inbox is proven.
    assert_eq!(
        call(&api, "/api/v1/auth/login", credentials.clone(), None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let verification_mail = get_mail(&mut receiver).await;
    let verification = token_from_email(&verification_mail);
    assert_eq!(
        call(&api, "/api/v1/auth/verify-email", json!({"token":verification}), None)
            .await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&api, "/api/v1/auth/verify-email", json!({"token":verification}), None)
            .await.status(),
        StatusCode::UNAUTHORIZED
    );

    let login = call(&api, "/api/v1/auth/login", credentials.clone(), None).await;
    assert_eq!(login.status(), StatusCode::OK);
    let raw = to_bytes(login.into_body(), 1024 * 1024).await.unwrap();
    let response: Value = serde_json::from_slice(&raw).unwrap();
    let _access = response["access_token"].as_str().unwrap();

    assert_eq!(
        call(&api, "/api/v1/auth/forgot-password", json!({"email":email}), None)
            .await.status(),
        StatusCode::ACCEPTED
    );
    let recovery_mail = get_mail(&mut receiver).await;
    let reset_token = token_from_email(&recovery_mail);
    assert_eq!(
        call(&api, "/api/v1/auth/reset-password",
            json!({"token":reset_token,"new_password":new_password}), None)
            .await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&api, "/api/v1/auth/reset-password",
            json!({"token":reset_token,"new_password":new_password}), None)
            .await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&api, "/api/v1/auth/login", credentials, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&api, "/api/v1/auth/login",
            json!({"email":email,"password":new_password}), None)
            .await.status(),
        StatusCode::OK
    );
    provider_task.abort();
}
