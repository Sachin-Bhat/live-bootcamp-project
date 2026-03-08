use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token);
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_token_stores_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "token-1".to_owned();

        assert_eq!(store.add_token(token.clone()).await, Ok(()));
        assert_eq!(store.contains_token(&token).await, Ok(true));
    }

    #[tokio::test]
    async fn contains_token_returns_false_if_token_not_present() {
        let store = HashsetBannedTokenStore::default();
        assert_eq!(store.contains_token("missing").await, Ok(false));
    }
}
