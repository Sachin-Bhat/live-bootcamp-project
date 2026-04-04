use dotenvy::dotenv;
use lazy_static::lazy_static;
use secrecy::SecretString;
use std::env as std_env;

// Define a lazily evaluated static. lazy_static is needed because std_env::var is not a const function.
lazy_static! {
    pub static ref JWT_SECRET: SecretString = set_token();
    pub static ref DATABASE_URL: SecretString = set_database_url();
    pub static ref POSTMARK_AUTH_TOKEN: SecretString = set_postmark_auth_token();
}

fn set_token() -> SecretString {
    dotenv().ok(); // Load environment variables
    let secret = match std_env::var(env::JWT_SECRET_ENV_VAR) {
        Ok(secret) => secret,
        Err(err) => {
            if cfg!(debug_assertions) {
                "local-dev-jwt-secret".to_owned()
            } else {
                panic!("JWT_SECRET must be set.: {err}");
            }
        }
    };

    if secret.trim().is_empty() {
        panic!("JWT_SECRET must not be empty.");
    }

    SecretString::new(secret.into_boxed_str())
}

fn set_database_url() -> SecretString {
    dotenv().ok();
    let url = std_env::var(env::DATABASE_URL_ENV_VAR).expect("DATABASE_URL must be set.");
    if url.is_empty() {
        panic!("DATABASE_URL must not be empty.");
    }
    SecretString::new(url.into_boxed_str())
}

fn set_postmark_auth_token() -> SecretString {
    dotenv().ok();
    SecretString::new(
        std_env::var(env::POSTMARK_AUTH_TOKEN_ENV_VAR)
            .expect("POSTMARK_AUTH_TOKEN must be set.")
            .into_boxed_str(),
    )
}

pub mod env {
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
    pub const POSTMARK_AUTH_TOKEN_ENV_VAR: &str = "POSTMARK_AUTH_TOKEN";
}

pub const JWT_COOKIE_NAME: &str = "jwt";

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
    pub mod email_client {
        use std::time::Duration;
        pub const BASE_URL: &str = "https://api.postmarkapp.com";
        pub const SENDER: &str = "bogdan@codeiron.io";
        pub const TIMEOUT: Duration = Duration::from_secs(10);
    }
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
    pub mod email_client {
        use std::time::Duration;
        pub const SENDER: &str = "test@email.com";
        pub const TIMEOUT: Duration = Duration::from_millis(200);
    }
}
