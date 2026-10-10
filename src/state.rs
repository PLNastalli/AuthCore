use jsonwebtoken::{DecodingKey, EncodingKey};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{collections::HashMap, env, error::Error, fs, sync::Arc, time::Duration};

pub struct JwtKeys {
    pub encoding: EncodingKey,
    pub signing_kid: String,
    pub verification_keys: HashMap<String, DecodingKey>,
    pub issuer: String,
    pub audience: String,
}

pub struct RecoveryMailer {
    pub api_key: String,
    pub from_email: String,
}

pub struct GoogleOAuth {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: redis::Client,
    pub jwt: Arc<JwtKeys>,
    pub public_origin: String,
    pub cookie_secure: bool,
    pub google: Option<Arc<GoogleOAuth>>,
    pub http: reqwest::Client,
    pub recovery_mailer: Option<Arc<RecoveryMailer>>,
    /// Local debug builds can run self-contained authentication tests without sending email.
    pub dev_skip_email_verification: bool,
    pub dummy_password_hash: Arc<String>,
    pub passwords: crate::security::PasswordService,
}

impl AppState {
    pub async fn from_env() -> Result<Self, Box<dyn Error>> {
        let database_url = env::var("DATABASE_URL")?;
        let redis_url = env::var("REDIS_URL")?;
        let private_path = env::var("JWT_PRIVATE_KEY_PATH")?;
        let public_path = env::var("JWT_PUBLIC_KEY_PATH")?;
        let issuer = env::var("JWT_ISSUER")?;
        let audience = env::var("JWT_AUDIENCE")?;
        let public_origin = env::var("PUBLIC_ORIGIN")?;
        let cookie_secure = env::var("COOKIE_SECURE")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()?;

        let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
        let dev_skip_email_verification = matches!(
            env::var("AUTHCORE_DEV_SKIP_EMAIL_VERIFICATION").as_deref(),
            Ok("true")
        );
        validate_http_security_config(
            &public_origin,
            cookie_secure,
            &bind_addr,
            dev_skip_email_verification,
        )?;
        let google = match (
            env::var("GOOGLE_CLIENT_ID").ok().filter(|v| !v.is_empty()),
            env::var("GOOGLE_CLIENT_SECRET")
                .ok()
                .filter(|v| !v.is_empty()),
            env::var("GOOGLE_REDIRECT_URI")
                .ok()
                .filter(|v| !v.is_empty()),
        ) {
            (None, None, None) => None,
            (Some(client_id), Some(client_secret), Some(redirect_uri)) => {
                let uri = reqwest::Url::parse(&redirect_uri)?;
                let expected = format!("{}/api/v1/oauth/google/callback", public_origin);
                if uri.as_str() != expected {
                    return Err(
                        "GOOGLE_REDIRECT_URI must match PUBLIC_ORIGIN and the callback route"
                            .into(),
                    );
                }
                Some(Arc::new(GoogleOAuth {
                    client_id,
                    client_secret,
                    redirect_uri,
                }))
            }
            _ => return Err(
                "configure GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI together"
                    .into(),
            ),
        };
        let recovery_mailer = match (
            env::var("RESEND_API_KEY").ok().filter(|v| !v.is_empty()),
            env::var("RESET_FROM_EMAIL").ok().filter(|v| !v.is_empty()),
        ) {
            (None, None) => None,
            (Some(api_key), Some(from_email)) => Some(Arc::new(RecoveryMailer {
                api_key,
                from_email,
            })),
            _ => return Err("configure RESEND_API_KEY and RESET_FROM_EMAIL together".into()),
        };
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let signing_kid = env::var("JWT_ACTIVE_KID").unwrap_or_else(|_| "primary".into());
        if !valid_kid(&signing_kid) {
            return Err("JWT_ACTIVE_KID must be 1-64 ASCII letters, digits, _, - or .".into());
        }
        let encoding = EncodingKey::from_rsa_pem(&fs::read(private_path)?)?;
        let mut verification_keys = HashMap::new();
        verification_keys.insert(
            signing_kid.clone(),
            DecodingKey::from_rsa_pem(&fs::read(public_path)?)?,
        );
        // Rotation: retain old public keys for as long as already-issued JWTs
        // can remain valid. New JWTs are always signed with JWT_ACTIVE_KID.
        if let Ok(json) = env::var("JWT_LEGACY_PUBLIC_KEYS_JSON") {
            let legacy: HashMap<String, String> = serde_json::from_str(&json)?;
            if legacy.len() > 16 {
                return Err("JWT legacy key count must not exceed 16".into());
            }
            for (kid, path) in legacy {
                if !valid_kid(&kid) || verification_keys.contains_key(&kid) {
                    return Err("invalid or duplicate JWT legacy key identifier".into());
                }
                verification_keys.insert(kid, DecodingKey::from_rsa_pem(&fs::read(path)?)?);
            }
        }
        let db = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&db).await?;
        let redis = redis::Client::open(redis_url)?;
        // No silent fail-open if the rate limiter is unavailable.
        let mut conn = redis.get_multiplexed_async_connection().await?;
        let _: String = redis::cmd("PING").query_async(&mut conn).await?;
        let passwords = crate::security::PasswordService::new(4);
        let dummy_password_hash = Arc::new(
            passwords
                .hash(crate::security::generate_refresh().0)
                .await
                .map_err(|_| "failed to initialize dummy Argon2 hash")?,
        );
        Ok(Self {
            db,
            redis,
            jwt: Arc::new(JwtKeys {
                encoding,
                signing_kid,
                verification_keys,
                issuer,
                audience,
            }),
            public_origin,
            cookie_secure,
            google,
            http,
            recovery_mailer,
            dev_skip_email_verification,
            dummy_password_hash,
            passwords,
        })
    }

    pub fn cookie_name(&self) -> &'static str {
        if self.cookie_secure {
            "__Host-authcore_refresh"
        } else {
            "authcore_refresh"
        }
    }

    pub fn cookie(&self, value: Option<&str>) -> String {
        match value {
            Some(token) => format!(
                "{}={token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=2592000{}",
                self.cookie_name(),
                if self.cookie_secure { "; Secure" } else { "" }
            ),
            None => format!(
                "{}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0{}",
                self.cookie_name(),
                if self.cookie_secure { "; Secure" } else { "" }
            ),
        }
    }
}

fn valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= 64
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod key_id_tests {
    use super::valid_kid;

    #[test]
    fn rejects_untrusted_key_identifiers() {
        for invalid in ["", "../secret", "bad kid", "a/b", "kid:bad", "é"] {
            assert!(!valid_kid(invalid), "{invalid}");
        }
        assert!(valid_kid("release-2026.10"));
    }
}

/// Validates canonical public origins rather than trusting textual prefixes.
/// Origin validation is security-sensitive because it governs cookies, OAuth and CSRF.
fn validate_http_security_config(
    origin: &str,
    cookie_secure: bool,
    bind_addr: &str,
    skip_verification: bool,
) -> Result<(), &'static str> {
    let url = reqwest::Url::parse(origin).map_err(|_| "invalid PUBLIC_ORIGIN URL")?;
    if url.origin().ascii_serialization() != origin
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("PUBLIC_ORIGIN must be a canonical origin without path, credentials or query");
    }
    let local_http = url.scheme() == "http"
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !local_http && url.scheme() != "https" {
        return Err("non-local PUBLIC_ORIGIN must use HTTPS");
    }
    if !cookie_secure && !local_http {
        return Err("insecure cookies are permitted only for localhost HTTP");
    }
    if skip_verification {
        let socket: std::net::SocketAddr = bind_addr
            .parse()
            .map_err(|_| "invalid BIND_ADDR for development bypass")?;
        if !cfg!(debug_assertions) || !local_http || !socket.ip().is_loopback() {
            return Err("email verification bypass requires a loopback-bound debug build");
        }
    }
    Ok(())
}

#[cfg(test)]
mod config_security_tests {
    use super::validate_http_security_config as validate;

    #[test]
    fn accepts_local_dev_origin_and_secure_production_origin() {
        assert!(validate("http://localhost:3000", false, "127.0.0.1:3000", false).is_ok());
        assert!(validate("http://127.0.0.1:3000", false, "127.0.0.1:3000", false).is_ok());
        assert!(validate("https://auth.example.com", true, "0.0.0.0:3000", false).is_ok());
    }

    #[test]
    fn rejects_prefix_impersonation_and_unsafe_origins() {
        for origin in [
            "http://localhost:3000.attacker.example",
            "http://localhost:3000@attacker.example",
            "https://auth.example.com/evil",
            "https://auth.example.com?token=foo",
            "https://auth.example.com/#fragment",
            "https://user:secret@auth.example.com",
            "http://auth.example.com",
        ] {
            assert!(
                validate(origin, false, "127.0.0.1:3000", false).is_err(),
                "{origin}"
            );
        }
        assert!(validate("https://auth.example.com", false, "127.0.0.1:3000", false).is_err());
    }

    #[test]
    fn development_bypass_cannot_bind_public_interface() {
        assert!(validate("http://localhost:3000", false, "0.0.0.0:3000", true).is_err());
        assert!(validate("http://localhost:3000", false, "not-an-address", true).is_err());
    }
}
