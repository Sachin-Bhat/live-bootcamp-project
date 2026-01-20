use auth_service::Application;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let app = Application::build("127.0.0.1:0")
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
    pub async fn signup(
        &self,
        email: &str,
        password: &str,
        requires_2fa: bool,
    ) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(&serde_json::json!({
                "email": email,
                "password": password,
                "requires2FA": requires_2fa,
            }))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn login(&self, email: &str, password: &str) -> reqwest::Response {
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

    pub async fn logout(&self, token: &str) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .header("Cookie", format!("jwt={}", token))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn verify_2fa(
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

    pub async fn verify_token(&self, token: &str) -> reqwest::Response {
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
