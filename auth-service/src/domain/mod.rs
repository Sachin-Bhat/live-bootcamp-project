mod data_stores;
mod error;
mod user;

pub use data_stores::*;
pub use error::*;
use serde::{Deserialize, Serialize};
pub use user::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email(String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Password(String);

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Email {
    pub fn parse(email: &str) -> Result<Self, EmailError> {
        if email.contains('@') && email.contains('.') && !email.is_empty() {
            Ok(Email(email.to_owned()))
        } else {
            Err(EmailError::InvalidEmail)
        }
    }
}

impl Password {
    pub fn parse(password: &str) -> Result<Self, PasswordError> {
        if password.len() >= 8
            && password.chars().any(|c| c.is_uppercase())
            && password.chars().any(|c| c.is_lowercase())
            && password.chars().any(|c| c.is_digit(10))
            && password.chars().any(|c| !c.is_alphanumeric() && c != ' ')
        {
            Ok(Password(password.to_owned()))
        } else {
            Err(PasswordError::InvalidPassword)
        }
    }
}

// Add unit tests for the `Email` and `Password` implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_email() {
        let email = Email::parse("test@example.com");
        assert!(email.is_ok());
    }

    #[test]
    fn test_parse_invalid_email() {
        let email = Email::parse("invalid_email");
        assert!(email.is_err());
    }

    #[test]
    fn test_as_ref_returns_inner_str() {
        let email = Email::parse("test@example.com").expect("Expected valid email");
        assert_eq!(email.as_ref(), "test@example.com");
    }

    #[test]
    fn test_parse_valid_password() {
        let password = Password::parse("Password123!");
        assert!(password.is_ok());
    }

    #[test]
    fn test_parse_invalid_password() {
        let password = Password::parse("pass");
        assert!(password.is_err());
    }

    #[test]
    fn test_as_ref_returns_inner_str_for_password() {
        let password = Password::parse("Password123!").expect("Expected valid password");
        assert_eq!(password.as_ref(), "Password123!");
    }
}
