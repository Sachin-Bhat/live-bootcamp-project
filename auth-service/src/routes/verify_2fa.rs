use axum::response::IntoResponse;

// Example route handler.
// For now we will simply return a 200 (OK) status code.
pub async fn verify_2fa() -> impl IntoResponse {
    reqwest::StatusCode::OK.into_response()
}
