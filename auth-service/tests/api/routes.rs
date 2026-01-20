use crate::helpers::TestApp;

// Tokio's test macro is used to run the test in an async environment
#[tokio::test]
async fn root_returns_auth_ui() {
    let app = TestApp::new().await;

    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}

// TODO: Implement tests for all other routes (signup, login, logout, verify-2fa, and verify-token)
// For now, simply assert that each route returns a 200 HTTP status code.

#[tokio::test]
async fn signup_returns_201() {
    let app = TestApp::new().await;

    let response = app
        .signup("test.user@example.com", "password123", false)
        .await;

    assert_eq!(response.status().as_u16(), 201);
}

#[tokio::test]
async fn login_returns_200() {
    let app = TestApp::new().await;

    let response = app.login("test.user@example.com", "password123").await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_2fa_returns_200() {
    let app = TestApp::new().await;

    let response = app
        .verify_2fa("test.user@example.com", "123456", "123456")
        .await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_token_returns_200() {
    let app = TestApp::new().await;

    let response = app.verify_token("123456").await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn logout_returns_200() {
    let app = TestApp::new().await;

    let response = app.logout("123456").await;

    assert_eq!(response.status().as_u16(), 200);
}
