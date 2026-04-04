use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use color_eyre::eyre::eyre;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode, UserStoreError},
    utils::auth::generate_auth_cookie,
};

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let LoginRequest { email, password } = request;

    let email = match Email::parse(email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let user_store = state.user_store.read().await;
    if let Err(error) = user_store.validate_user(&email, &password).await {
        let api_error = match error {
            UserStoreError::UserNotFound | UserStoreError::InvalidCredentials => {
                AuthAPIError::IncorrectCredentials
            }
            UserStoreError::UnexpectedError(e) => AuthAPIError::UnexpectedError(e),
            _ => AuthAPIError::UnexpectedError(eyre!("unexpected user store error")),
        };
        return (jar, Err(api_error));
    }

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(UserStoreError::UserNotFound) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
        Err(UserStoreError::UnexpectedError(e)) => {
            return (jar, Err(AuthAPIError::UnexpectedError(e)))
        }
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(eyre!("{e}")))),
    };
    drop(user_store);

    let (jar, response) = match user.requires_2fa() {
        true => handle_2fa(&user.email, &state, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    };

    (jar, response.map(IntoResponse::into_response))
}

#[tracing::instrument(name = "Handle 2FA login", skip_all)]
async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    let mut two_fa_code_store = state.two_fa_code_store.write().await;
    if let Err(e) = two_fa_code_store
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    let email_client = state.email_client.read().await;
    let subject = "Your 2FA code";
    let content = format!(
        "Your code is {}. Login attempt ID: {}",
        two_fa_code.as_ref().expose_secret(),
        login_attempt_id.as_ref().expose_secret()
    );
    if let Err(e) = email_client.send_email(email, subject, &content).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e)));
    }

    (
        jar,
        Ok((
            StatusCode::PARTIAL_CONTENT,
            Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
                message: "2FA required".to_owned(),
                login_attempt_id: login_attempt_id.as_ref().expose_secret().to_owned(),
            })),
        )),
    )
}

#[tracing::instrument(name = "Handle login without 2FA", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e))),
    };
    let jar = jar.add(auth_cookie);

    (jar, Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))))
}

#[derive(Deserialize, Debug)]
pub struct LoginRequest {
    pub email: SecretString,
    pub password: SecretString,
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
