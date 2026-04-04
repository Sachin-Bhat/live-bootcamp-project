use std::collections::HashSet;

use secrecy::{ExposeSecret, SecretString};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[tokio::test]
    async fn add_token_stores_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = SecretString::new("token-1".to_owned().into_boxed_str());

        assert_eq!(store.add_token(token.clone()).await, Ok(()));
        assert_eq!(store.contains_token(&token).await, Ok(true));
    }

    #[tokio::test]
    async fn contains_token_returns_false_if_token_not_present() {
        let store = HashsetBannedTokenStore::default();
        let token = SecretString::new("missing".to_owned().into_boxed_str());
        assert_eq!(store.contains_token(&token).await, Ok(false));
    }
}
