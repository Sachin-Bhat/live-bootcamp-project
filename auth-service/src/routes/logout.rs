use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{CookieJar, cookie::Cookie};

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    // Validate JWT token by calling `validate_token` from the auth service.
    // If the token is valid you can ignore the returned claims for now.
    // Return AuthAPIError::InvalidToken is validation fails.

    let banned_token_store = state.banned_token_store.read().await;
    let _claims = match validate_token(&token, banned_token_store.as_ref()).await {
        Ok(claims) => claims,
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    };
    drop(banned_token_store);

    let mut banned_token_store = state.banned_token_store.write().await;
    if banned_token_store.add_token(token).await.is_err() {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }
    drop(banned_token_store);

    // Add a new `Cookie` to the `CookieJar` with the same name and value as the current one,
    // but with an expiration date in the past so that the browser deletes it immediately.
    let jar = jar.remove(Cookie::from(JWT_COOKIE_NAME));

    (jar, Ok(StatusCode::OK))
}
