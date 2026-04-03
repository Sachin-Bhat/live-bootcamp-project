mod data_stores;
pub mod email_client;
mod error;
mod password;
mod user;

pub use data_stores::*;
pub use email_client::*;
pub use error::*;
pub use password::*;
use serde::{Deserialize, Serialize};
pub use user::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email(String);

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Email {
    pub fn parse(email: String) -> Result<Self, EmailError> {
        if email.contains('@') && email.contains('.') && !email.is_empty() {
            Ok(Email(email))
        } else {
            Err(EmailError::InvalidEmail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_email() {
        let email = Email::parse("test@example.com".to_owned());
        assert!(email.is_ok());
    }

    #[test]
    fn test_parse_invalid_email() {
        let email = Email::parse("invalid_email".to_owned());
        assert!(email.is_err());
    }

    #[test]
    fn test_as_ref_returns_inner_str() {
        let email = Email::parse("test@example.com".to_owned()).expect("Expected valid email");
        assert_eq!(email.as_ref(), "test@example.com");
    }
}
