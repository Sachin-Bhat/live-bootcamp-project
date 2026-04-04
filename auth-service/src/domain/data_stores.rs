use color_eyre::eyre::{Context, Report, Result, bail};
use rand::RngExt;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use uuid::Uuid;

use super::{Email, User};

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(
        &self,
        email: &Email,
        raw_password: &SecretString,
    ) -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError>;
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for BannedTokenStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(SecretString);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> {
        Uuid::parse_str(&id).wrap_err("Invalid login attempt ID")?;
        Ok(Self(SecretString::new(id.into_boxed_str())))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(SecretString::new(
            Uuid::new_v4().to_string().into_boxed_str(),
        ))
    }
}

impl AsRef<SecretString> for LoginAttemptId {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

#[derive(Clone, Debug)]
pub struct TwoFACode(SecretString);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> {
        if code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()) {
            Ok(Self(SecretString::new(code.into_boxed_str())))
        } else {
            bail!("2FA code must be a 6-digit number");
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let mut rng = rand::rng();
        let code: u32 = rng.random_range(100_000..=999_999);
        Self(SecretString::new(
            format!("{code:06}").into_boxed_str(),
        ))
    }
}

impl AsRef<SecretString> for TwoFACode {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}
