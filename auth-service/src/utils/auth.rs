use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use color_eyre::eyre::{Context, Result, eyre};
use jsonwebtoken::{DecodingKey, EncodingKey, Validation, decode, encode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::domain::{BannedTokenStore, Email};

use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};

// This value determines how long the JWT auth token is valid for
pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

// Create cookie with a new JWT auth token
#[tracing::instrument(name = "Generate auth cookie", skip_all)]
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

// Create cookie and set the value to the passed-in token string
fn create_auth_cookie(token: String) -> Cookie<'static> {
    Cookie::build((JWT_COOKIE_NAME, token))
        .path("/") // apply cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .same_site(SameSite::Lax) // send cookie with "same-site" requests, and with "cross-site" top-level navigations.
        .build()
}

// Create JWT auth token
fn generate_auth_token(email: &Email) -> Result<String> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .ok_or_else(|| eyre!("Failed to create token duration"))?;

    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or_else(|| eyre!("Failed to compute token expiration time"))?
        .timestamp();

    // Cast exp to a usize, which is what Claims expects
    let exp: usize = exp
        .try_into()
        .wrap_err("Failed to cast expiration timestamp")?;

    let sub = email.as_ref().expose_secret().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims).wrap_err("Failed to create JWT token")
}

// Check if JWT auth token is valid by decoding it using the JWT secret
#[tracing::instrument(name = "Validate token", skip_all)]
pub async fn validate_token(
    token: &str,
    banned_token_store: &(dyn BannedTokenStore + Send + Sync),
) -> Result<Claims> {
    let secret_token = SecretString::new(token.to_owned().into_boxed_str());
    if banned_token_store
        .contains_token(&secret_token)
        .await
        .map_err(|e| eyre!("Failed to check banned token store: {e}"))?
    {
        return Err(eyre!("Token is banned"));
    }

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("Failed to decode JWT token")
}

// Create JWT auth token by encoding claims using the JWT secret
fn create_token(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::hashset_banned_token_store::HashsetBannedTokenStore;
    use secrecy::SecretString;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let token = generate_auth_token(&email).unwrap();
        let banned_token_store = HashsetBannedTokenStore::default();
        let result = validate_token(&token, &banned_token_store).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = "invalid_token".to_owned();
        let banned_token_store = HashsetBannedTokenStore::default();
        let result = validate_token(&token, &banned_token_store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let token = generate_auth_token(&email).unwrap();
        let mut banned_token_store = HashsetBannedTokenStore::default();
        banned_token_store
            .add_token(SecretString::new(token.clone().into_boxed_str()))
            .await
            .unwrap();

        let result = validate_token(&token, &banned_token_store).await;
        assert!(result.is_err());
    }
}
