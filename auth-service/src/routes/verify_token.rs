use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Deserialize;

use crate::{domain::AuthAPIError, utils::auth::validate_token};

pub async fn verify_token(
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let token = request.token.trim();
    if token.is_empty() {
        return Err(AuthAPIError::InvalidCredentials);
    }

    validate_token(token)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize, Debug)]
pub struct VerifyTokenRequest {
    pub token: String,
}
