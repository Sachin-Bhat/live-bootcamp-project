use std::sync::Arc;

use auth_service::{Application, app_state::AppState, services::HashmapUserStore};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let user_store = HashmapUserStore::default();
        let app_state = AppState::new(Arc::new(RwLock::new(user_store)));

        let app = Application::build(app_state, "127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = reqwest::Client::new(); // create a new Reqwest http client instance

        // Create new `TestApp` instance and return it
        Self {
            address,
            http_client,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    // Implement helper functions for all other routes (signup, login, logout, verify-2fa, and verify-token)
    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(&serde_json::json!(body))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login(&self, email: &str, password: &str) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(&serde_json::json!({
                "email": email,
                "password": password,
            }))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self, token: &str) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .header("Cookie", format!("jwt={}", token))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa(
        &self,
        email: &str,
        login_attempt_id: &str,
        two_fa_code: &str,
    ) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(&serde_json::json!({
                "email": email,
                "loginAttemptId": login_attempt_id,
                "2FACode": two_fa_code,
            }))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token(&self, token: &str) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .json(&serde_json::json!({
                "token": token,
            }))
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
