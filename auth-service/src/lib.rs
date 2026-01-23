use std::error::Error;

use axum::Router;
use axum::{routing::post, serve::Serve};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;
use crate::routes::{login, logout, signup, verify_2fa, verify_token};
use app_state::AppState;

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        let assets_dir =
            ServeDir::new("assets").not_found_service(ServeFile::new("assets/index.html"));
        let router = Router::new()
            .fallback_service(assets_dir)
            .route("/signup", post(signup))
            .route("/verify-2fa", post(verify_2fa))
            .route("/verify-token", post(verify_token))
            .route("/login", post(login))
            .route("/logout", post(logout))
            .with_state(app_state);
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
