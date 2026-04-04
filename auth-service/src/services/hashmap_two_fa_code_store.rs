use std::collections::HashMap;

use secrecy::ExposeSecret;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<String, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes
            .insert(email.as_ref().expose_secret().to_owned(), (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email.as_ref().expose_secret());
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes
            .get(email.as_ref().expose_secret())
            .cloned()
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore};

    use super::HashmapTwoFACodeStore;

    fn make_email(s: &str) -> Email {
        Email::parse(SecretString::new(s.to_owned().into_boxed_str())).expect("valid email")
    }

    #[tokio::test]
    async fn add_code_stores_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = make_email("test@example.com");
        let attempt = LoginAttemptId::default();
        let code = TwoFACode::default();

        store
            .add_code(email.clone(), attempt.clone(), code.clone())
            .await
            .expect("add code should succeed");

        let (stored_attempt, stored_code) =
            store.get_code(&email).await.expect("code should exist");
        assert_eq!(stored_attempt, attempt);
        assert_eq!(stored_code, code);
    }

    #[tokio::test]
    async fn remove_code_deletes_existing_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = make_email("test@example.com");

        store
            .add_code(
                email.clone(),
                LoginAttemptId::default(),
                TwoFACode::default(),
            )
            .await
            .expect("add code should succeed");
        store
            .remove_code(&email)
            .await
            .expect("remove code should succeed");

        assert!(store.get_code(&email).await.is_err());
    }

    #[tokio::test]
    async fn get_code_returns_error_if_missing() {
        let store = HashmapTwoFACodeStore::default();
        let email = make_email("missing@example.com");

        let result = store.get_code(&email).await;
        assert!(matches!(
            result,
            Err(crate::domain::TwoFACodeStoreError::LoginAttemptIdNotFound)
        ));
    }
}
