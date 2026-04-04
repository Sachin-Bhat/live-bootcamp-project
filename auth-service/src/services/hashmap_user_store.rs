use std::collections::HashMap;

use secrecy::{ExposeSecret, SecretString};

use crate::domain::{Email, User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(user.email.as_ref().expose_secret()) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users
                .insert(user.email.as_ref().expose_secret().to_owned(), user);
            Ok(())
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email.as_ref().expose_secret())
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(
        &self,
        email: &Email,
        raw_password: &SecretString,
    ) -> Result<(), UserStoreError> {
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
    use secrecy::SecretString;

    fn make_email(s: &str) -> Email {
        Email::parse(SecretString::new(s.to_owned().into_boxed_str())).expect("valid email")
    }

    async fn make_password(s: &str) -> HashedPassword {
        HashedPassword::parse(SecretString::new(s.to_owned().into_boxed_str()))
            .await
            .expect("valid password")
    }

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new(make_email("test@example.com"), make_password("Password123!").await, false);

        assert_eq!(store.add_user(user.clone()).await, Ok(()));
        assert_eq!(
            store.add_user(user).await,
            Err(UserStoreError::UserAlreadyExists)
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let email = make_email("test@example.com");
        let password = make_password("Password123!").await;
        let user = User::new(email.clone(), password, false);

        store.add_user(user).await.unwrap();

        let found = store.get_user(&email).await.unwrap();
        assert_eq!(
            found.email.as_ref().expose_secret(),
            email.as_ref().expose_secret()
        );
        assert!(
            found
                .password
                .verify_raw_password(&SecretString::new("Password123!".to_owned().into_boxed_str()))
                .await
                .is_ok()
        );
        let missing = make_email("missing@example.com");
        assert!(matches!(
            store.get_user(&missing).await,
            Err(UserStoreError::UserNotFound)
        ));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let email = make_email("test@example.com");
        let user = User::new(email.clone(), make_password("Password123!").await, false);

        store.add_user(user).await.unwrap();

        assert_eq!(
            store
                .validate_user(
                    &email,
                    &SecretString::new("Password123!".to_owned().into_boxed_str())
                )
                .await,
            Ok(())
        );
        assert_eq!(
            store
                .validate_user(
                    &email,
                    &SecretString::new("wrong-password".to_owned().into_boxed_str())
                )
                .await,
            Err(UserStoreError::InvalidCredentials)
        );
        let missing = make_email("missing@example.com");
        assert_eq!(
            store
                .validate_user(
                    &missing,
                    &SecretString::new("password123".to_owned().into_boxed_str())
                )
                .await,
            Err(UserStoreError::UserNotFound)
        );
    }
}
