use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

// Example route handler.
// For now we will simply return a 201 (CREATED) status code.
pub async fn signup(Json(request): Json<SignupRequest>) -> impl IntoResponse {
    StatusCode::CREATED.into_response()
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    // used to serialize/de-serialize a field with the given name instead of its Rust name.
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
