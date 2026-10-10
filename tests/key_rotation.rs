use authcore::{
    security,
    state::{AppState, JwtKeys},
};
use axum::http::{header, HeaderMap, HeaderValue};
use jsonwebtoken::{DecodingKey, EncodingKey};
use std::{collections::HashMap, fs, sync::Arc};
use uuid::Uuid;

#[tokio::test]
async fn old_tokens_validate_during_key_rollover_and_stop_after_retirement() {
    if std::env::var("DATABASE_URL").is_err() {
        return;
    }
    let original = AppState::from_env()
        .await
        .expect("PostgreSQL and Redis required");
    let user = Uuid::new_v4();
    let session = Uuid::new_v4();
    let old_token = security::issue_access(&original, user, session).unwrap();

    let mut rotated = original.clone();
    let mut old_and_new = HashMap::new();
    old_and_new.insert(
        "primary".to_owned(),
        DecodingKey::from_rsa_pem(&fs::read(".dev-keys/jwt-public.pem").unwrap()).unwrap(),
    );
    old_and_new.insert(
        "next".to_owned(),
        DecodingKey::from_rsa_pem(&fs::read(".dev-keys/next-public.pem").unwrap()).unwrap(),
    );
    rotated.jwt = Arc::new(JwtKeys {
        encoding: EncodingKey::from_rsa_pem(&fs::read(".dev-keys/next-private.pem").unwrap())
            .unwrap(),
        signing_kid: "next".to_owned(),
        verification_keys: old_and_new,
        issuer: original.jwt.issuer.clone(),
        audience: original.jwt.audience.clone(),
    });

    let mut old_headers = HeaderMap::new();
    old_headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {old_token}")).unwrap(),
    );
    assert_eq!(
        security::verify_access(&rotated, &old_headers).unwrap(),
        (user, session)
    );

    let next_token = security::issue_access(&rotated, user, session).unwrap();
    let mut new_headers = HeaderMap::new();
    new_headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {next_token}")).unwrap(),
    );
    assert!(security::verify_access(&original, &new_headers).is_err());
    assert_eq!(
        security::verify_access(&rotated, &new_headers).unwrap(),
        (user, session)
    );

    let mut retired = rotated.clone();
    let mut new_only = HashMap::new();
    new_only.insert(
        "next".into(),
        DecodingKey::from_rsa_pem(&fs::read(".dev-keys/next-public.pem").unwrap()).unwrap(),
    );
    retired.jwt = Arc::new(JwtKeys {
        encoding: EncodingKey::from_rsa_pem(&fs::read(".dev-keys/next-private.pem").unwrap())
            .unwrap(),
        signing_kid: "next".into(),
        verification_keys: new_only,
        issuer: original.jwt.issuer.clone(),
        audience: original.jwt.audience.clone(),
    });
    assert!(security::verify_access(&retired, &old_headers).is_err());
    assert_eq!(
        security::verify_access(&retired, &new_headers).unwrap(),
        (user, session)
    );
}
