use std::sync::Arc;

use auth_service::{
    Application,
    app_state::AppState,
    services::{
        hashmap_two_fa_code_store::HashmapTwoFACodeStore, hashmap_user_store::HashmapUserStore,
        hashset_banned_token_store::HashsetBannedTokenStore, mock_email_client::MockEmailClient,
    },
    utils::constants::prod,
};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    // Here we are using ip 0.0.0.0 so the service is listening on all the configured network interfaces.
    // This is needed for Docker to work, which we will add later on.
    // See: https://stackoverflow.com/questions/39525820/docker-port-forwarding-not-working

    let user_store = HashmapUserStore::default();
    let banned_token_store = HashsetBannedTokenStore::default();
    let two_fa_code_store = HashmapTwoFACodeStore::default();
    let email_client = MockEmailClient;
    let app_state = AppState::new(
        Arc::new(RwLock::new(Box::new(user_store))),
        Arc::new(RwLock::new(Box::new(banned_token_store))),
        Arc::new(RwLock::new(Box::new(two_fa_code_store))),
        Arc::new(RwLock::new(Box::new(email_client))),
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build application");

    app.run().await.expect("Failed to run application");
}
