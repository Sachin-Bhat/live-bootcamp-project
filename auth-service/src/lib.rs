use std::error::Error;

use axum::Router;
use axum::{response::IntoResponse, routing::post, serve::Serve};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(address: &str) -> Result<Self, Box<dyn Error>> {
        // Move the Router definition from `main.rs` to here.
        // Also, remove the `hello` route.
        // We don't need it at this point!
        let assets_dir =
            ServeDir::new("assets").not_found_service(ServeFile::new("assets/index.html"));
        let router = Router::new()
            .fallback_service(assets_dir)
            .route("/signup", post(signup))
            .route("/verify-2fa", post(verify_2fa))
            .route("/verify-token", post(verify_token))
            .route("/login", post(login))
            .route("/logout", post(logout));
        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it
        Ok(Self { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

// Example route handler.
// For now we will simply return a 201 (CREATED) status code.
async fn signup() -> impl IntoResponse {
    reqwest::StatusCode::CREATED.into_response()
}

// TODO: Add all other route handlers with appropriate status codes
async fn login() -> impl IntoResponse {
    reqwest::StatusCode::OK.into_response()
}

async fn logout() -> impl IntoResponse {
    reqwest::StatusCode::OK.into_response()
}

async fn verify_2fa() -> impl IntoResponse {
    reqwest::StatusCode::OK.into_response()
}

async fn verify_token() -> impl IntoResponse {
    reqwest::StatusCode::OK.into_response()
}
