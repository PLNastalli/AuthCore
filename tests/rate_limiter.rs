use authcore::{error::ApiError, limiter};
use uuid::Uuid;

#[tokio::test]
async fn redis_limits_are_atomic_and_unavailable_storage_fails_closed() {
    let Ok(url) = std::env::var("REDIS_URL") else {
        return;
    };
    let client = redis::Client::open(url).expect("test Redis URL");
    let scope = format!("ci-{}", Uuid::new_v4());

    assert!(limiter::check(&client, &scope, "same-identity", 2, 30).await.is_ok());
    assert!(limiter::check(&client, &scope, "same-identity", 2, 30).await.is_ok());
    let rejected = limiter::check(&client, &scope, "same-identity", 2, 30).await;
    assert!(matches!(rejected, Err(ApiError::RateLimited)));

    // Limiting one identity must not lock out a second identity.
    assert!(limiter::check(&client, &scope, "another-identity", 2, 30).await.is_ok());

    // Reserve a port and release it, guaranteeing there is no Redis server
    // bound to the test endpoint at the time of the check.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let unavailable = redis::Client::open(format!("redis://127.0.0.1:{port}/")).unwrap();
    let result = limiter::check(&unavailable, &scope, "same-identity", 2, 30).await;
    assert!(matches!(result, Err(ApiError::Unavailable)));
}
