use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;

use crate::{app_state::AppState, domain::AuthAPIError, utils::auth::validate_token};

pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let token = request.token.trim();
    if token.is_empty() {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let banned_token_store = state.banned_token_store.read().await;
    validate_token(token, banned_token_store.as_ref())
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize, Debug)]
pub struct VerifyTokenRequest {
    pub token: String,
}
