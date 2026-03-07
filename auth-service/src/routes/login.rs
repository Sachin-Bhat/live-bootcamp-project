use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, UserStore, UserStoreError},
    utils::auth::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let LoginRequest { email, password } = request;

    let email = match Email::parse(email.as_ref().to_owned()) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };
    let password = match password {
        Some(password) => password,
        None => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let user_store = state.user_store.read().await;
    if let Err(error) = user_store
        .validate_user(email.as_ref(), password.as_ref())
        .await
    {
        let api_error = match error {
            UserStoreError::UserNotFound | UserStoreError::InvalidCredentials => {
                AuthAPIError::IncorrectCredentials
            }
            _ => AuthAPIError::UnexpectedError,
        };
        return (jar, Err(api_error));
    }

    // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.
    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    let updated_jar = jar.add(auth_cookie);

    (
        updated_jar,
        Ok((
            StatusCode::OK,
            Json(LoginResponse {
                message: "Login successful!".to_string(),
                login_attempt_id: None,
            }),
        )
            .into_response()),
    )
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
