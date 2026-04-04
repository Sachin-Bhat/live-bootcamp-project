use std::str::FromStr;
use std::sync::Arc;

use auth_service::{
    Application,
    app_state::{AppState, BannedTokenStoreType, TwoFACodeStoreType},
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
    utils::constants::{DATABASE_URL, test},
};
use reqwest::Client;
use reqwest::cookie::Jar;
use secrecy::{ExposeSecret, SecretString};
use sqlx::{Connection, Executor, PgPool};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
use tokio::sync::RwLock;
use uuid::Uuid;
use wiremock::MockServer;

pub struct TestApp {
    pub address: String,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub email_server: MockServer,
    pub db_name: String,
    pub clean_up_called: bool,
}

impl TestApp {
    pub async fn new() -> Self {
        let (pg_pool, db_name) = configure_postgresql().await;
        let user_store = Arc::new(RwLock::new(Box::new(PostgresUserStore::new(pg_pool.clone())) as Box<_>));
        let banned_token_store: BannedTokenStoreType =
            Arc::new(RwLock::new(Box::new(PostgresBannedTokenStore::new(pg_pool.clone()))));
        let two_fa_code_store: TwoFACodeStoreType =
            Arc::new(RwLock::new(Box::new(PostgresTwoFACodeStore::new(pg_pool))));

        let email_server = MockServer::start().await;
        let base_url = email_server.uri();
        let email_client = Arc::new(RwLock::new(
            Box::new(configure_postmark_email_client(base_url)) as Box<_>,
        ));

        let app_state = AppState::new(
            user_store,
            banned_token_store.clone(),
            two_fa_code_store.clone(),
            email_client,
        );

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build application");

        let address = format!("http://{}", app.address.clone());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        Self {
            address,
            banned_token_store,
            two_fa_code_store,
            cookie_jar,
            http_client,
            email_server,
            db_name,
            clean_up_called: false,
        }
    }

    pub async fn clean_up(&mut self) {
        delete_database(&self.db_name).await;
        self.clean_up_called = true;
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/signup", &self.address))
            .json(&serde_json::json!(body))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self, token: &str) -> reqwest::Response {
        self.http_client
            .post(format!("{}/logout", &self.address))
            .header("Cookie", format!("jwt={}", token))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.clean_up_called && !std::thread::panicking() {
            panic!("TestApp::clean_up() was not called before dropping TestApp!");
        }
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

fn configure_postmark_email_client(base_url: String) -> PostmarkEmailClient {
    let postmark_auth_token = SecretString::new("auth_token".to_owned().into_boxed_str());

    let sender = Email::parse(SecretString::new(
        test::email_client::SENDER.to_owned().into_boxed_str(),
    ))
    .unwrap();

    let http_client = Client::builder()
        .timeout(test::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(base_url, sender, postmark_auth_token, http_client)
}

async fn configure_postgresql() -> (PgPool, String) {
    let postgresql_conn_url = DATABASE_URL.expose_secret().to_owned();

    let db_name = Uuid::new_v4().to_string();

    configure_database(&postgresql_conn_url, &db_name).await;

    let postgresql_conn_url_with_db = format!("{}/{}", postgresql_conn_url, db_name);
    let pool_url = SecretString::new(postgresql_conn_url_with_db.into_boxed_str());

    let pool = get_postgres_pool(&pool_url)
        .await
        .expect("Failed to create Postgres connection pool!");

    (pool, db_name)
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    let connection = PgPoolOptions::new()
        .connect(db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");

    let db_conn_string = format!("{}/{}", db_conn_string, db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str) {
    let postgresql_conn_url: String = DATABASE_URL.expose_secret().to_owned();

    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url)
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                  AND pid <> pg_backend_pid();
                "#,
                db_name
            )
            .as_str(),
        )
        .await
        .expect("Failed to terminate active connections.");

    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}
