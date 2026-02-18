use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, UserStore, UserStoreError},
};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let LoginRequest { email, password } = request;

    let email = Email::parse(email.as_ref()).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = password.ok_or(AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.read().await;
    user_store
        .validate_user(email.as_ref(), password.as_ref())
        .await
        .map_err(|error| match error {
            UserStoreError::UserNotFound | UserStoreError::InvalidCredentials => {
                AuthAPIError::IncorrectCredentials
            }
            _ => AuthAPIError::UnexpectedError,
        })?;

    Ok((
        StatusCode::OK,
        Json(LoginResponse {
            message: "Login successful!".to_string(),
            login_attempt_id: None,
        }),
    )
        .into_response())
}

#[derive(Deserialize, Serialize, Debug)]
pub struct LoginRequest {
    pub email: Email,
    pub password: Option<Password>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LoginResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: Option<String>,
}
