use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User, UserStore},
};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let SignupRequest {
        email,
        password,
        requires_2fa,
    } = request;

    let email = Email::parse(email.as_ref()).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password =
        Password::parse(password.as_ref()).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let mut user_store = state.user_store.write().await;

    // early return AuthAPIError::UserAlreadyExists if email exists in user_store.
    if user_store.get_user(email.as_ref()).await.is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    // Create a new `User` instance using data in the `request`
    let user = User::new(email, password, requires_2fa);

    // instead of using unwrap, early return AuthAPIError::UnexpectedError if add_user() fails.
    user_store
        .add_user(user)
        .await
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SignupRequest {
    pub email: Email,
    pub password: Password,
    // used to serialize/de-serialize a field with the given name instead of its Rust name.
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SignupResponse {
    pub message: String,
}
