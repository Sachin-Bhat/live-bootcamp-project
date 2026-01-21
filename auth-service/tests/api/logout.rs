use crate::helpers::TestApp;

// For now, simply assert that each route returns a 200 HTTP status code.
#[tokio::test]
async fn logout_returns_200() {
    let app = TestApp::new().await;

    let response = app.post_logout("123456").await;

    assert_eq!(response.status().as_u16(), 200);
}
