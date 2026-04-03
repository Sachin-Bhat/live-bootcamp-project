use sqlx::PgPool;

use crate::{
    domain::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct PostgresBannedTokenStore {
    pool: PgPool,
}

impl PostgresBannedTokenStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for PostgresBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let expires_at = chrono::Utc::now()
            + chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
                .ok_or(BannedTokenStoreError::UnexpectedError)?;

        sqlx::query!(
            "INSERT INTO banned_tokens (token, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            token,
            expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let result = sqlx::query!(
            "SELECT EXISTS(SELECT 1 FROM banned_tokens WHERE token = $1 AND expires_at > NOW()) AS \"exists!\"",
            token,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(result.exists)
    }
}
