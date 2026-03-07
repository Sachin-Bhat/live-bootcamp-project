use auth_service::{ErrorResponse, utils::constants::JWT_COOKIE_NAME};

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    let _random_email = get_random_email(); // Call helper method to generate email

    // add more malformed input test cases
    let test_cases = [serde_json::json!({
        "password": "password123"
    })];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await; // call `post_signup`
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let email = get_random_email();
    let password = "password123";

    // Test with invalid email format
    let invalid_email_payload = serde_json::json!({
        "email": "not-an-email",
        "password": password
    });

    let response = app.post_login(&invalid_email_payload).await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "Expected 400 for invalid email format"
    );

    // Test with missing password
    let missing_password_payload = serde_json::json!({
        "email": email
    });

    let response = app.post_login(&missing_password_payload).await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "Expected 400 for missing password"
    );
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;
    let email = get_random_email();
    let password = "Password123!";
    let wrong_password = "WrongPassword123!";

    // First, register a user to ensure the email exists in the database
    let signup_payload = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false
    });
    let signup_response = app.post_signup(&signup_payload).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    // Attempt login with correct email but wrong password
    let login_payload = serde_json::json!({
        "email": email,
        "password": wrong_password
    });

    let response = app.post_login(&login_payload).await;
    assert_eq!(
        response.status().as_u16(),
        401,
        "Expected 401 for incorrect credentials"
    );

    // Optionally verify error message contains expected content
    let error_response: ErrorResponse = response.json().await.unwrap();
    assert!(error_response.error.contains("Incorrect credentials"));
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}
