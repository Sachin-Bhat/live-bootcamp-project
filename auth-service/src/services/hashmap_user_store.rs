use std::collections::HashMap;

use crate::domain::{User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(user.email.as_ref()) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.as_ref().to_owned(), user);
            Ok(())
        }
    }

    async fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &str, raw_password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        user.password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Email, HashedPassword};

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_owned()).expect("valid email"),
            HashedPassword::parse("Password123!".to_owned())
                .await
                .expect("valid password"),
            false,
        );

        assert_eq!(store.add_user(user.clone()).await, Ok(()));
        assert_eq!(
            store.add_user(user).await,
            Err(UserStoreError::UserAlreadyExists)
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_owned()).expect("valid email"),
            HashedPassword::parse("Password123!".to_owned())
                .await
                .expect("valid password"),
            false,
        );

        store.add_user(user).await.unwrap();

        let found = store.get_user("test@example.com").await.unwrap();
        assert_eq!(found.email.as_ref(), "test@example.com");
        assert!(found.password.verify_raw_password("Password123!").await.is_ok());
        assert!(matches!(
            store.get_user("missing@example.com").await,
            Err(UserStoreError::UserNotFound)
        ));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_owned()).expect("valid email"),
            HashedPassword::parse("Password123!".to_owned())
                .await
                .expect("valid password"),
            false,
        );

        store.add_user(user).await.unwrap();

        assert_eq!(
            store.validate_user("test@example.com", "Password123!").await,
            Ok(())
        );
        assert_eq!(
            store
                .validate_user("test@example.com", "wrong-password")
                .await,
            Err(UserStoreError::InvalidCredentials)
        );
        assert_eq!(
            store
                .validate_user("missing@example.com", "password123")
                .await,
            Err(UserStoreError::UserNotFound)
        );
    }
}
