use axum::response::IntoResponse;

// Example route handler.
// For now we will simply return a 201 (CREATED) status code.
pub async fn signup() -> impl IntoResponse {
    reqwest::StatusCode::CREATED.into_response()
}
