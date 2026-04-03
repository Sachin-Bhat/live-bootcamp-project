use sqlx::PgPool;

use crate::domain::{
    Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError,
};

const TEN_MINUTES_IN_SECONDS: i64 = 600;

pub struct PostgresTwoFACodeStore {
    pool: PgPool,
}

impl PostgresTwoFACodeStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for PostgresTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let expires_at = chrono::Utc::now()
            + chrono::Duration::try_seconds(TEN_MINUTES_IN_SECONDS)
                .ok_or(TwoFACodeStoreError::UnexpectedError)?;

        sqlx::query!(
            r#"
            INSERT INTO two_fa_codes (email, login_attempt_id, code, expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (email) DO UPDATE
                SET login_attempt_id = EXCLUDED.login_attempt_id,
                    code = EXCLUDED.code,
                    expires_at = EXCLUDED.expires_at
            "#,
            email.as_ref(),
            login_attempt_id.as_ref(),
            code.as_ref(),
            expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        sqlx::query!(
            "DELETE FROM two_fa_codes WHERE email = $1",
            email.as_ref(),
        )
        .execute(&self.pool)
        .await
        .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let row = sqlx::query!(
            "SELECT login_attempt_id, code FROM two_fa_codes WHERE email = $1 AND expires_at > NOW()",
            email.as_ref(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        let login_attempt_id = LoginAttemptId::parse(row.login_attempt_id)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let code = TwoFACode::parse(row.code)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok((login_attempt_id, code))
    }
}
