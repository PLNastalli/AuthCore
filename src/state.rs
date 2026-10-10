use jsonwebtoken::{DecodingKey, EncodingKey};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{env, error::Error, fs, sync::Arc, time::Duration};

pub struct JwtKeys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
    pub issuer: String,
    pub audience: String,
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: redis::Client,
    pub jwt: Arc<JwtKeys>,
    pub public_origin: String,
    pub cookie_secure: bool,
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

        if !cookie_secure && !public_origin.starts_with("http://localhost:")
            && !public_origin.starts_with("http://127.0.0.1:")
        {
            return Err("insecure refresh cookies are only permitted on localhost".into());
        }
        if !public_origin.starts_with("https://") && cookie_secure
            && !public_origin.starts_with("http://localhost:")
            && !public_origin.starts_with("http://127.0.0.1:")
        {
            return Err("production PUBLIC_ORIGIN must use HTTPS".into());
        }
        let encoding = EncodingKey::from_rsa_pem(&fs::read(private_path)?)?;
        let decoding = DecodingKey::from_rsa_pem(&fs::read(public_path)?)?;
        let db = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&database_url).await?;
        sqlx::migrate!("./migrations").run(&db).await?;
        let redis = redis::Client::open(redis_url)?;
        // No silent fail-open if the rate limiter is unavailable.
        let mut conn = redis.get_multiplexed_async_connection().await?;
        let _: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(Self {
            db, redis,
            jwt: Arc::new(JwtKeys { encoding, decoding, issuer, audience }),
            public_origin, cookie_secure,
        })
    }

    pub fn cookie_name(&self) -> &'static str {
        if self.cookie_secure { "__Host-authcore_refresh" } else { "authcore_refresh" }
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
            )
        }
    }
}
