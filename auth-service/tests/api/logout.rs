use auth_service::{ErrorResponse, utils::constants::JWT_COOKIE_NAME};
use reqwest::Url;

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let mut app = TestApp::new().await;

    let response = app
        .http_client
        .post(format!("{}/logout", app.address))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status().as_u16(), 400);

    let body: ErrorResponse = response.json().await.expect("valid error response");
    assert_eq!(body.error, "Missing token");

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout("123456").await;

    assert_eq!(response.status().as_u16(), 401);

    let body: ErrorResponse = response.json().await.expect("valid error response");
    assert_eq!(body.error, "Invalid token");

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
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
    let response = app.post_login(&login_payload).await;
    assert_eq!(response.status().as_u16(), 200);
    let token = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("auth cookie should be set on login")
        .value()
        .to_owned();

    let response = app.post_logout(&token).await;
    assert_eq!(response.status().as_u16(), 200);
    let set_cookie_header = response
        .headers()
        .get("set-cookie")
        .expect("set-cookie header should be present")
        .to_str()
        .expect("set-cookie should be valid UTF-8");
    assert!(set_cookie_header.contains(&format!("{JWT_COOKIE_NAME}=")));
    assert!(set_cookie_header.contains("Max-Age=0"));

    let banned_token_store = app.banned_token_store.read().await;
    assert_eq!(
        banned_token_store.contains_token(&token).await,
        Ok(true),
        "token should be added to banned token store after logout"
    );
    drop(banned_token_store);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
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
    let response = app.post_login(&login_payload).await;
    assert_eq!(response.status().as_u16(), 200);

    let response = app
        .http_client
        .post(format!("{}/logout", app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    assert_eq!(response.status().as_u16(), 200);

    let response = app
        .http_client
        .post(format!("{}/logout", app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    assert_eq!(response.status().as_u16(), 400);
    let body: ErrorResponse = response.json().await.expect("valid error response");
    assert_eq!(body.error, "Missing token");

    app.clean_up().await;
}
