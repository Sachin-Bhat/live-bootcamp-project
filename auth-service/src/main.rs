use std::sync::Arc;

use auth_service::{
    Application,
    app_state::AppState,
    domain::Email,
    get_postgres_pool,
    services::{
        postmark_email_client::PostmarkEmailClient,
        data_stores::{
            postgres_user_store::PostgresUserStore,
            postgres_banned_token_store::PostgresBannedTokenStore,
            postgres_two_fa_code_store::PostgresTwoFACodeStore,
        },
    },
    utils::{
        constants::{DATABASE_URL, POSTMARK_AUTH_TOKEN, prod},
        tracing::init_tracing,
    },
};
use reqwest::Client;
use secrecy::SecretString;
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    color_eyre::install().expect("Failed to install color_eyre");
    init_tracing().expect("Failed to initialize tracing");

    let pg_pool = configure_postgresql().await;

    let user_store = Arc::new(RwLock::new(Box::new(PostgresUserStore::new(pg_pool.clone())) as Box<_>));
    let banned_token_store = Arc::new(RwLock::new(Box::new(PostgresBannedTokenStore::new(pg_pool.clone())) as Box<_>));
    let two_fa_code_store = Arc::new(RwLock::new(Box::new(PostgresTwoFACodeStore::new(pg_pool)) as Box<_>));
    let email_client = Arc::new(RwLock::new(Box::new(configure_postmark_email_client()) as Box<_>));

    let app_state = AppState::new(user_store, banned_token_store, two_fa_code_store, email_client);

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build application");

    app.run().await.expect("Failed to run application");
}

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_postmark_email_client() -> PostmarkEmailClient {
    let http_client = Client::builder()
        .timeout(prod::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    let sender = Email::parse(SecretString::new(
        prod::email_client::SENDER.to_owned().into_boxed_str(),
    ))
    .expect("Invalid sender email");

    PostmarkEmailClient::new(
        prod::email_client::BASE_URL.to_owned(),
        sender,
        POSTMARK_AUTH_TOKEN.clone(),
        http_client,
    )
}
