mod data_stores;
pub mod email_client;
mod error;
mod password;
mod user;

pub use data_stores::*;
pub use email_client::*;
pub use error::*;
pub use password::*;
pub use user::*;

use color_eyre::eyre::{Result, eyre};
use secrecy::{ExposeSecret, SecretString};
use std::hash::Hash;
use validator::ValidateEmail;

#[derive(Debug, Clone)]
pub struct Email(SecretString);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Eq for Email {}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl AsRef<SecretString> for Email {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl Email {
    pub fn parse(s: SecretString) -> Result<Self> {
        if s.expose_secret().validate_email() {
            Ok(Email(s))
        } else {
            Err(eyre!("{} is not a valid email address", s.expose_secret()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Email;
    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::{SeedableRng, rngs::SmallRng};
    use secrecy::SecretString;

    #[test]
    fn empty_string_is_rejected() {
        let email = SecretString::new("".to_owned().into_boxed_str());
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn email_missing_at_symbol_is_rejected() {
        let email = SecretString::new("ursuladomain.com".to_owned().into_boxed_str());
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn email_missing_subject_is_rejected() {
        let email = SecretString::new("@domain.com".to_owned().into_boxed_str());
        assert!(Email::parse(email).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl quickcheck::Arbitrary for ValidEmailFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = SmallRng::seed_from_u64(seed);
            let email = SafeEmail().fake_with_rng(&mut rng);
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(SecretString::new(valid_email.0.into_boxed_str())).is_ok()
    }
}
