use crate::helpers::TestApp;

// For now, simply assert that each route returns a 200 HTTP status code.
#[tokio::test]
async fn login_returns_200() {
    let app = TestApp::new().await;

    let response = app.post_login("test.user@example.com", "password123").await;

    assert_eq!(response.status().as_u16(), 200);
}
