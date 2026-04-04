use auth_service::{ErrorResponse, utils::constants::JWT_COOKIE_NAME};
use secrecy::SecretString;

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let test_cases = [serde_json::json!({})];

    for test_case in &test_cases {
        let response = app.post_verify_token(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_empty_token() {
    let mut app = TestApp::new().await;

    let response = app
        .post_verify_token(&serde_json::json!({ "token": "" }))
        .await;

    assert_eq!(response.status().as_u16(), 400);
    let body: ErrorResponse = response.json().await.expect("valid error response");
    assert_eq!(body.error, "Invalid credentials");

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    let response = app
        .post_verify_token(&serde_json::json!({ "token": "invalid" }))
        .await;

    assert_eq!(response.status().as_u16(), 401);
    let body: ErrorResponse = response.json().await.expect("valid error response");
    assert_eq!(body.error, "Invalid token");

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_token_is_valid() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "Password123!";
    let signup_payload = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false
    });
    let signup_response = app.post_signup(&signup_payload).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    let login_payload = serde_json::json!({
        "email": email,
        "password": password
    });
    let login_response = app.post_login(&login_payload).await;
    assert_eq!(login_response.status().as_u16(), 200);

    let token = login_response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("auth cookie should be set on login")
        .value()
        .to_owned();

    let response = app
        .post_verify_token(&serde_json::json!({ "token": token }))
        .await;
    assert_eq!(response.status().as_u16(), 200);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "Password123!";
    let signup_payload = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false
    });
    let signup_response = app.post_signup(&signup_payload).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    let login_payload = serde_json::json!({
        "email": email,
        "password": password
    });
    let login_response = app.post_login(&login_payload).await;
    assert_eq!(login_response.status().as_u16(), 200);

    let token = login_response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("auth cookie should be set on login")
        .value()
        .to_owned();

    let mut banned_token_store = app.banned_token_store.write().await;
    banned_token_store
        .add_token(SecretString::new(token.clone().into_boxed_str()))
        .await
        .expect("token should be insertable into banned token store");
    drop(banned_token_store);

    let response = app
        .post_verify_token(&serde_json::json!({ "token": token }))
        .await;
    assert_eq!(response.status().as_u16(), 401);
    let body: ErrorResponse = response.json().await.expect("valid error response");
    assert_eq!(body.error, "Invalid token");

    app.clean_up().await;
}
