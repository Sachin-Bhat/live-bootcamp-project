use crate::helpers::TestApp;

// For now, simply assert that each route returns a 201 HTTP status code.
#[tokio::test]
async fn signup_returns_201() {
    let app = TestApp::new().await;

    let response = app
        .signup("test.user@example.com", "password123", false)
        .await;

    assert_eq!(response.status().as_u16(), 201);
}
