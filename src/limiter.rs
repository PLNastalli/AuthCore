use crate::error::ApiError;
use redis::Script;
use sha2::{Digest, Sha256};

pub async fn check(redis: &redis::Client, scope: &str, identity: &str, max: i64, seconds: i64) -> Result<(), ApiError> {
    let mut conn = redis.get_multiplexed_async_connection().await
        .map_err(|_| ApiError::Unavailable)?;
    let digest = Sha256::digest(identity.as_bytes());
    let key = format!("authcore:rate:{scope}:{digest:x}");
    let script = Script::new(r#"
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
        return count
    "#);
    let count: i64 = script.key(key).arg(seconds)
        .invoke_async(&mut conn).await.map_err(|_| ApiError::Unavailable)?;
    if count > max {
        return Err(ApiError::RateLimited);
    }
    Ok(())
}
