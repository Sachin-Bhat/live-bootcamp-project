use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use secrecy::SecretString;

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    let banned_token_store = state.banned_token_store.read().await;
    let _claims = match validate_token(&token, banned_token_store.as_ref()).await {
        Ok(claims) => claims,
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    };
    drop(banned_token_store);

    let secret_token = SecretString::new(token.into_boxed_str());
    let mut banned_token_store = state.banned_token_store.write().await;
    if let Err(e) = banned_token_store.add_token(secret_token).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }
    drop(banned_token_store);

    let jar = jar.remove(Cookie::from(JWT_COOKIE_NAME));

    (jar, Ok(StatusCode::OK))
}
