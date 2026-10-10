use jsonwebtoken::{DecodingKey, EncodingKey};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{env, error::Error, fs, sync::Arc, time::Duration};

pub struct JwtKeys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
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

        if !cookie_secure
            && !public_origin.starts_with("http://localhost:")
            && !public_origin.starts_with("http://127.0.0.1:")
        {
            return Err("insecure refresh cookies are only permitted on localhost".into());
        }
        if !public_origin.starts_with("https://")
            && cookie_secure
            && !public_origin.starts_with("http://localhost:")
            && !public_origin.starts_with("http://127.0.0.1:")
        {
            return Err("production PUBLIC_ORIGIN must use HTTPS".into());
        }
        let local_origin = public_origin.starts_with("http://localhost:")
            || public_origin.starts_with("http://127.0.0.1:");
        let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
        let loopback_bind = bind_addr.starts_with("127.0.0.1:") || bind_addr.starts_with("[::1]:");
        let dev_skip_email_verification = matches!(
            env::var("AUTHCORE_DEV_SKIP_EMAIL_VERIFICATION").as_deref(),
            Ok("true")
        );
        if dev_skip_email_verification && !(cfg!(debug_assertions) && local_origin && loopback_bind)
        {
            return Err(
                "email-verification bypass is restricted to debug builds bound to loopback".into(),
            );
        }
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
        let encoding = EncodingKey::from_rsa_pem(&fs::read(private_path)?)?;
        let decoding = DecodingKey::from_rsa_pem(&fs::read(public_path)?)?;
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
                decoding,
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
