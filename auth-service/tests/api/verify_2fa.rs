use auth_service::{
    ErrorResponse,
    domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore},
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
};
use secrecy::{ExposeSecret, SecretString};
use wiremock::{Mock, ResponseTemplate, matchers::{method, path}};

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let valid_login_attempt_id = LoginAttemptId::default();
    let valid_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "loginAttemptId": valid_login_attempt_id.as_ref().expose_secret(),
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": valid_email,
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": valid_email,
            "loginAttemptId": valid_login_attempt_id.as_ref().expose_secret()
        }),
        serde_json::json!({
            "email": 42,
            "loginAttemptId": valid_login_attempt_id.as_ref().expose_secret(),
            "2FACode": "123456"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
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

    let valid_login_attempt_id = LoginAttemptId::default();
    let valid_two_fa_code = TwoFACode::default();

    let test_cases = [
        serde_json::json!({
            "email": "not-an-email",
            "loginAttemptId": valid_login_attempt_id.as_ref().expose_secret(),
            "2FACode": valid_two_fa_code.as_ref().expose_secret()
        }),
        serde_json::json!({
            "email": get_random_email(),
            "loginAttemptId": "not-a-uuid",
            "2FACode": valid_two_fa_code.as_ref().expose_secret()
        }),
        serde_json::json!({
            "email": get_random_email(),
            "loginAttemptId": valid_login_attempt_id.as_ref().expose_secret(),
            "2FACode": "12ab"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        let error_response: ErrorResponse = response.json().await.unwrap();
        assert!(error_response.error.contains("Invalid credentials"));
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "Password123!";

    let signup_payload = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true
    });
    let signup_response = app.post_signup(&signup_payload).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_payload = serde_json::json!({
        "email": email,
        "password": password
    });
    let login_response = app.post_login(&login_payload).await;
    assert_eq!(login_response.status().as_u16(), 206);

    let two_fa_response = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("login should return TwoFactorAuthResponse");

    let invalid_two_fa_code = "000000";
    let verify_payload = serde_json::json!({
        "email": email,
        "loginAttemptId": two_fa_response.login_attempt_id,
        "2FACode": invalid_two_fa_code
    });
    let verify_response = app.post_verify_2fa(&verify_payload).await;

    assert_eq!(verify_response.status().as_u16(), 401);
    let body: ErrorResponse = verify_response.json().await.expect("valid error response");
    assert_eq!(body.error, "Incorrect credentials");

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "Password123!";

    let signup_payload = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true
    });
    let signup_response = app.post_signup(&signup_payload).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;

    let login_payload = serde_json::json!({
        "email": email,
        "password": password
    });

    let first_login = app.post_login(&login_payload).await;
    assert_eq!(first_login.status().as_u16(), 206);
    let first_two_fa_response = first_login
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("first login should return TwoFactorAuthResponse");

    let parsed_email = Email::parse(SecretString::new(email.clone().into_boxed_str()))
        .expect("email should parse");
    let first_code = {
        let store = app.two_fa_code_store.read().await;
        let (_, code) = TwoFACodeStore::get_code(&**store, &parsed_email)
            .await
            .expect("2FA entry should exist after first login");
        code
    };

    let second_login = app.post_login(&login_payload).await;
    assert_eq!(second_login.status().as_u16(), 206);

    let verify_payload = serde_json::json!({
        "email": email,
        "loginAttemptId": first_two_fa_response.login_attempt_id,
        "2FACode": first_code.as_ref().expose_secret()
    });
    let verify_response = app.post_verify_2fa(&verify_payload).await;

    assert_eq!(verify_response.status().as_u16(), 401);
    let body: ErrorResponse = verify_response.json().await.expect("valid error response");
    assert_eq!(body.error, "Incorrect credentials");

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "Password123!";

    let signup_payload = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true
    });
    let signup_response = app.post_signup(&signup_payload).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_payload = serde_json::json!({
        "email": email,
        "password": password
    });
    let login_response = app.post_login(&login_payload).await;
    assert_eq!(login_response.status().as_u16(), 206);
    let two_fa_response = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("login should return TwoFactorAuthResponse");

    let parsed_email = Email::parse(SecretString::new(email.clone().into_boxed_str()))
        .expect("email should parse");
    let stored_code = {
        let store = app.two_fa_code_store.read().await;
        let (_, code) = TwoFACodeStore::get_code(&**store, &parsed_email)
            .await
            .expect("2FA entry should exist after login");
        code
    };

    let verify_payload = serde_json::json!({
        "email": email,
        "loginAttemptId": two_fa_response.login_attempt_id,
        "2FACode": stored_code.as_ref().expose_secret()
    });
    let verify_response = app.post_verify_2fa(&verify_payload).await;

    assert_eq!(verify_response.status().as_u16(), 200);
    let auth_cookie = verify_response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("auth cookie should be set on successful 2FA verification");
    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "Password123!";

    let signup_payload = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true
    });
    let signup_response = app.post_signup(&signup_payload).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_payload = serde_json::json!({
        "email": email,
        "password": password
    });
    let login_response = app.post_login(&login_payload).await;
    assert_eq!(login_response.status().as_u16(), 206);
    let two_fa_response = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("login should return TwoFactorAuthResponse");

    let parsed_email = Email::parse(SecretString::new(email.clone().into_boxed_str()))
        .expect("email should parse");
    let stored_code = {
        let store = app.two_fa_code_store.read().await;
        let (_, code) = TwoFACodeStore::get_code(&**store, &parsed_email)
            .await
            .expect("2FA entry should exist after login");
        code
    };

    let verify_payload = serde_json::json!({
        "email": email,
        "loginAttemptId": two_fa_response.login_attempt_id,
        "2FACode": stored_code.as_ref().expose_secret()
    });

    let first_verify_response = app.post_verify_2fa(&verify_payload).await;
    assert_eq!(first_verify_response.status().as_u16(), 200);

    let second_verify_response = app.post_verify_2fa(&verify_payload).await;
    assert_eq!(second_verify_response.status().as_u16(), 401);
    let body: ErrorResponse = second_verify_response
        .json()
        .await
        .expect("valid error response");
    assert_eq!(body.error, "Incorrect credentials");

    app.clean_up().await;
}
