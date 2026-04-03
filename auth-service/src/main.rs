use std::sync::Arc;

use auth_service::{
    Application,
    app_state::AppState,
    get_postgres_pool,
    services::{
        mock_email_client::MockEmailClient,
        data_stores::{
            postgres_user_store::PostgresUserStore,
            postgres_banned_token_store::PostgresBannedTokenStore,
            postgres_two_fa_code_store::PostgresTwoFACodeStore,
        },
    },
    utils::constants::{DATABASE_URL, prod},
};
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;

    let user_store = Arc::new(RwLock::new(Box::new(PostgresUserStore::new(pg_pool.clone())) as Box<_>));
    let banned_token_store = Arc::new(RwLock::new(Box::new(PostgresBannedTokenStore::new(pg_pool.clone())) as Box<_>));
    let two_fa_code_store = Arc::new(RwLock::new(Box::new(PostgresTwoFACodeStore::new(pg_pool)) as Box<_>));
    let email_client = Arc::new(RwLock::new(Box::new(MockEmailClient) as Box<_>));
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
