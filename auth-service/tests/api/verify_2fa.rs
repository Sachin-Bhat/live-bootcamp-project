use crate::helpers::TestApp;

// For now, simply assert that each route returns a 200 HTTP status code.
#[tokio::test]
async fn verify_2fa_returns_200() {
    let app = TestApp::new().await;

    let response = app
        .post_verify_2fa("test.user@example.com", "123456", "123456")
        .await;

    assert_eq!(response.status().as_u16(), 200);
}
