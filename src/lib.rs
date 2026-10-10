pub mod error;
pub mod handlers;
pub mod limiter;
pub mod oauth;
pub mod recovery;
pub mod security;
pub mod verification;
pub mod state;

use axum::{
    body::Body,
    http::Request,
    routing::{delete, get, post},
    Router,
};
use state::AppState;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
        .route("/openapi.json", get(handlers::openapi))
        .route("/api/v1/auth/register", post(handlers::register))
        .route("/api/v1/auth/verify-email", post(verification::verify))
        .route("/api/v1/auth/resend-verification", post(verification::resend))
        .route("/api/v1/oauth/google/start", get(oauth::start))
        .route("/api/v1/oauth/google/callback", get(oauth::callback))
        .route("/api/v1/auth/login", post(handlers::login))
        .route("/api/v1/auth/refresh", post(handlers::refresh))
        .route(
            "/api/v1/auth/forgot-password",
            post(recovery::forgot_password),
        )
        .route(
            "/api/v1/auth/reset-password",
            post(recovery::reset_password),
        )
        .route("/api/v1/auth/logout", post(handlers::logout))
        .route("/api/v1/auth/logout-all", post(handlers::logout_all))
        .route(
            "/api/v1/auth/change-password",
            post(handlers::change_password),
        )
        .route("/api/v1/auth/me", get(handlers::me))
        .route("/api/v1/auth/sessions", get(handlers::sessions))
        .route(
            "/api/v1/auth/sessions/{id}",
            delete(handlers::revoke_session),
        )
        .layer(RequestBodyLimitLayer::new(16 * 1024))
        .layer(TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
            // OAuth callback URIs contain sensitive authorization codes.
            // Do not include the query string or request headers in traces.
            tracing::info_span!("http_request", method = %request.method(), path = %request.uri().path())
        }))
        .with_state(state)
}
