use auth_service::{
    ErrorResponse,
    routes::SignupResponse,
};

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let _random_email = get_random_email();

    let test_cases = [serde_json::json!({
        "password": "password123",
        "requires2FA": true
    })];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
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
async fn should_return_201_if_valid_input() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let test_case = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": false
    });

    let response = app.post_signup(&test_case).await;

    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let input = [
        serde_json::json!({
            "email": "",
            "password": "Password123!",
            "requires2FA": false
        }),
        serde_json::json!({
            "email": "email",
            "password": "Password123!",
            "requires2FA": false
        }),
        serde_json::json!({
            "email": "email@example.com",
            "password": "password123",
            "requires2FA": false
        }),
    ];

    for i in input.iter() {
        let response = app.post_signup(i).await;
        assert_eq!(response.status().as_u16(), 400, "Failed for input: {:?}", i);

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let mut app = TestApp::new().await;

    let payload = serde_json::json!({
        "email": "test@example.com",
        "password": "Password123!",
        "requires2FA": false
    });

    let response = app.post_signup(&payload).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_signup(&payload).await;
    assert_eq!(response.status().as_u16(), 409);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );

    app.clean_up().await;
}
