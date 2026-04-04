use auth_service::{
    ErrorResponse,
    domain::{Email, TwoFACodeStore},
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
};
use secrecy::{ExposeSecret, SecretString};
use wiremock::{Mock, ResponseTemplate, matchers::{method, path}};

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({ "password": "password123" }),
        serde_json::json!({ "email": get_random_email() }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
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
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let password = "password123";

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

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "Password123!";
    let wrong_password = "WrongPassword123!";

    let signup_payload = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false
    });
    let signup_response = app.post_signup(&signup_payload).await;
    assert_eq!(signup_response.status().as_u16(), 201);

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

    let error_response: ErrorResponse = response.json().await.unwrap();
    assert!(error_response.error.contains("Incorrect credentials"));

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new().await;

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

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let has_auth_cookie = response
        .cookies()
        .any(|cookie| cookie.name() == JWT_COOKIE_NAME);
    assert!(
        !has_auth_cookie,
        "JWT cookie should not be set for 2FA flow"
    );

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let email = Email::parse(SecretString::new(random_email.into_boxed_str()))
        .expect("email should parse");
    let two_fa_code_store = app.two_fa_code_store.read().await;
    let (stored_login_attempt_id, _) = TwoFACodeStore::get_code(&**two_fa_code_store, &email)
        .await
        .expect("2FA code entry should exist");
    assert_eq!(
        stored_login_attempt_id.as_ref().expose_secret(),
        &json_body.login_attempt_id
    );

    drop(two_fa_code_store);
    app.clean_up().await;
}
