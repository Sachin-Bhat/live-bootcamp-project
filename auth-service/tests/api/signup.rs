use auth_service::{
    ErrorResponse,
    routes::{SignupRequest, SignupResponse},
};

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let _random_email = get_random_email(); // Call helper method to generate email

    // add more malformed input test cases
    let test_cases = [serde_json::json!({
        "password": "password123",
        "requires2FA": true
    })];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await; // call `post_signup`
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email(); // Call helper method to generate email

    let test_case = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&test_case).await; // call `post_signup`

    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // The signup route should return a 400 HTTP status code if an invalid input is sent.
    // The input is considered invalid if:
    // - The email is empty or does not contain '@'
    // - The password is less than 8 characters

    // Create an array of invalid inputs. Then, iterate through the array and
    // make HTTP calls to the signup route. Assert a 400 HTTP status code is returned.
    let app = TestApp::new().await;
    let input = vec![
        SignupRequest {
            email: "".to_owned(),
            password: "password".to_owned(),
            requires_2fa: false,
        },
        SignupRequest {
            email: "email".to_owned(),
            password: "password".to_owned(),
            requires_2fa: false,
        },
        SignupRequest {
            email: "email@example.com".to_owned(),
            password: "pass".to_owned(),
            requires_2fa: false,
        },
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
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let app = TestApp::new().await;

    let response = app
        .post_signup(&SignupRequest {
            email: "test@example.com".to_owned(),
            password: "password123".to_owned(),
            requires_2fa: false,
        })
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let response = app
        .post_signup(&SignupRequest {
            email: "test@example.com".to_owned(),
            password: "password123".to_owned(),
            requires_2fa: false,
        })
        .await;

    assert_eq!(response.status().as_u16(), 409);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
}
