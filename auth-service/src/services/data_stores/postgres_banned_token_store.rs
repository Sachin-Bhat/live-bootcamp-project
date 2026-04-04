use color_eyre::eyre::eyre;
use secrecy::{ExposeSecret, SecretString};
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
    #[tracing::instrument(name = "Adding banned token to PostgreSQL", skip_all)]
    async fn add_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {
        let expires_at = chrono::Utc::now()
            + chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
                .ok_or_else(|| BannedTokenStoreError::UnexpectedError(eyre!("Failed to create duration")))?;

        sqlx::query!(
            "INSERT INTO banned_tokens (token, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            token.expose_secret(),
            expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| BannedTokenStoreError::UnexpectedError(e.into()))?;

        Ok(())
    }

    #[tracing::instrument(name = "Checking banned token in PostgreSQL", skip_all)]
    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        let result = sqlx::query!(
            "SELECT EXISTS(SELECT 1 FROM banned_tokens WHERE token = $1 AND expires_at > NOW()) AS \"exists!\"",
            token.expose_secret(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| BannedTokenStoreError::UnexpectedError(e.into()))?;

        Ok(result.exists)
    }
}
