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
        let key = user.email.as_ref().expose_secret().to_owned();
        if let std::collections::hash_map::Entry::Vacant(e) = self.users.entry(key) {
            e.insert(user);
            Ok(())
        } else {
            Err(UserStoreError::UserAlreadyExists)
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

    fn make_email(s: &str) -> Email {
        Email::parse(SecretString::new(s.to_owned().into_boxed_str())).expect("valid email")
    }

    fn make_password(s: &str) -> SecretString {
        SecretString::new(s.to_owned().into_boxed_str())
    }

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new(
            make_email("test@example.com"),
            HashedPassword::parse(make_password("Password123!"))
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
        let email = make_email("test@example.com");
        let user = User::new(
            email.clone(),
            HashedPassword::parse(make_password("Password123!"))
                .await
                .expect("valid password"),
            false,
        );

        store.add_user(user).await.unwrap();

        let found = store.get_user(&email).await.unwrap();
        assert_eq!(
            found.email.as_ref().expose_secret(),
            "test@example.com"
        );
        assert!(found.password.verify_raw_password(&make_password("Password123!")).await.is_ok());
        assert!(matches!(
            store.get_user(&make_email("missing@example.com")).await,
            Err(UserStoreError::UserNotFound)
        ));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let email = make_email("test@example.com");
        let user = User::new(
            email.clone(),
            HashedPassword::parse(make_password("Password123!"))
                .await
                .expect("valid password"),
            false,
        );

        store.add_user(user).await.unwrap();

        assert_eq!(
            store.validate_user(&email, &make_password("Password123!")).await,
            Ok(())
        );
        assert_eq!(
            store.validate_user(&email, &make_password("wrong-password")).await,
            Err(UserStoreError::InvalidCredentials)
        );
        assert_eq!(
            store
                .validate_user(&make_email("missing@example.com"), &make_password("password123"))
                .await,
            Err(UserStoreError::UserNotFound)
        );
    }
}
