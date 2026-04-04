use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::{Context, Result};
use secrecy::{ExposeSecret, SecretString};

#[derive(Debug, Clone)]
pub struct HashedPassword(SecretString);

impl PartialEq for HashedPassword {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl HashedPassword {
    #[tracing::instrument(name = "HashedPassword::parse", skip_all)]
    pub async fn parse(s: SecretString) -> Result<HashedPassword> {
        if s.expose_secret().is_empty() {
            return Err(color_eyre::eyre::eyre!("Password must not be empty"));
        }
        if s.expose_secret().len() < 8 {
            return Err(color_eyre::eyre::eyre!(
                "Password must be at least 8 characters"
            ));
        }
        let exposed = s.expose_secret();
        if !exposed.chars().any(|c| c.is_uppercase())
            || !exposed.chars().any(|c| c.is_lowercase())
            || !exposed.chars().any(|c| c.is_ascii_digit())
            || !exposed.chars().any(|c| !c.is_alphanumeric() && c != ' ')
        {
            return Err(color_eyre::eyre::eyre!(
                "Password does not meet complexity requirements"
            ));
        }

        let hash = compute_password_hash(&s).await?;
        Ok(HashedPassword(hash))
    }

    #[tracing::instrument(name = "HashedPassword::parse_password_hash", skip_all)]
    pub fn parse_password_hash(hash: SecretString) -> Result<HashedPassword> {
        PasswordHash::new(hash.expose_secret())
            .wrap_err("Invalid password hash")?;
        Ok(HashedPassword(hash))
    }

    #[tracing::instrument(name = "Verify raw password", skip_all)]
    pub async fn verify_raw_password(&self, password_candidate: &SecretString) -> Result<()> {
        let current_span: tracing::Span = tracing::Span::current();
        let password_hash = self.0.expose_secret().to_owned();
        let password_candidate = password_candidate.expose_secret().to_owned();

        tokio::task::spawn_blocking(move || {
            current_span.in_scope(|| {
                let expected_password_hash =
                    PasswordHash::new(&password_hash).wrap_err("invalid password hash")?;
                Argon2::default()
                    .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                    .wrap_err("failed to verify password hash")
            })
        })
        .await?
    }
}

impl AsRef<SecretString> for HashedPassword {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &SecretString) -> Result<SecretString> {
    let current_span: tracing::Span = tracing::Span::current();
    let password = password.expose_secret().to_owned();

    tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None).wrap_err("invalid argon2 params")?,
            )
            .hash_password(password.as_bytes(), &salt)
            .wrap_err("failed to hash password")?
            .to_string();
            Ok(SecretString::new(password_hash.into_boxed_str()))
        })
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::HashedPassword;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm, Argon2, Params, PasswordHasher, Version,
    };
    use quickcheck::Gen;
    use secrecy::SecretString;

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = SecretString::new("".to_owned().into_boxed_str());
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = SecretString::new("1234567".to_owned().into_boxed_str());
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[test]
    fn can_parse_valid_argon2_hash() {
        let raw_password = "TestPassword123!";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );
        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hashed_password = HashedPassword::parse_password_hash(
            SecretString::new(hash_string.clone().into_boxed_str()),
        )
        .unwrap();

        use secrecy::ExposeSecret;
        assert_eq!(hashed_password.as_ref().expose_secret(), hash_string.as_str());
        assert!(hashed_password.as_ref().expose_secret().starts_with("$argon2id$v=19$"));
    }

    #[tokio::test]
    async fn can_verify_raw_password() {
        use secrecy::ExposeSecret;
        let raw_password = "TestPassword123!";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );
        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hashed_password = HashedPassword::parse_password_hash(
            SecretString::new(hash_string.clone().into_boxed_str()),
        )
        .unwrap();

        assert_eq!(hashed_password.as_ref().expose_secret(), hash_string.as_str());
        assert!(hashed_password.as_ref().expose_secret().starts_with("$argon2id$v=19$"));

        let result = hashed_password
            .verify_raw_password(&SecretString::new(raw_password.to_owned().into_boxed_str()))
            .await;
        assert!(result.is_ok());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub SecretString);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
            const DIGITS: &[u8] = b"0123456789";
            const SPECIAL: &[u8] = b"!@#$%^&*";

            let upper = *g.choose(UPPER).unwrap() as char;
            let lower = *g.choose(LOWER).unwrap() as char;
            let digit = *g.choose(DIGITS).unwrap() as char;
            let special = *g.choose(SPECIAL).unwrap() as char;
            let extra: String = (0..4)
                .map(|_| *g.choose(LOWER).unwrap() as char)
                .collect();

            Self(SecretString::new(
                format!("{upper}{lower}{digit}{special}{extra}").into_boxed_str(),
            ))
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(HashedPassword::parse(valid_password.0))
            .is_ok()
    }
}
