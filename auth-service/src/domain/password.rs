use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use serde::Serialize;
use std::error::Error;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HashedPassword(String);

impl HashedPassword {
    pub async fn parse(s: String) -> Result<Self, String> {
        if s.is_empty() {
            return Err("Password must not be empty".to_string());
        }
        if s.len() < 8 {
            return Err("Password must be at least 8 characters".to_string());
        }
        if !s.chars().any(|c| c.is_uppercase())
            || !s.chars().any(|c| c.is_lowercase())
            || !s.chars().any(|c| c.is_ascii_digit())
            || !s.chars().any(|c| !c.is_alphanumeric() && c != ' ')
        {
            return Err("Password does not meet complexity requirements".to_string());
        }

        let hash = compute_password_hash(&s)
            .await
            .map_err(|e| e.to_string())?;
        Ok(HashedPassword(hash))
    }

    pub fn parse_password_hash(hash: String) -> Result<HashedPassword, String> {
        PasswordHash::new(&hash).map_err(|e| e.to_string())?;
        Ok(HashedPassword(hash))
    }

    pub async fn verify_raw_password(
        &self,
        password_candidate: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let password_hash = self.as_ref().to_owned();
        let password_candidate = password_candidate.to_owned();

        tokio::task::spawn_blocking(move || {
            let expected_password_hash = PasswordHash::new(&password_hash)
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
            Argon2::default()
                .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
        })
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?
    }
}

async fn compute_password_hash(
    password: &str,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let password = password.to_owned();

    tokio::task::spawn_blocking(move || -> Result<String, Box<dyn Error + Send + Sync>> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None)?,
        )
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
        Ok(password_hash)
    })
    .await
    .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?
}

impl AsRef<str> for HashedPassword {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::HashedPassword;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm, Argon2, Params, PasswordHasher, Version,
    };
    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::SeedableRng;

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = "".to_owned();
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = "1234567".to_owned();
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

        let hashed_password = HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(hashed_password.as_ref(), hash_string.as_str());
        assert!(hashed_password.as_ref().starts_with("$argon2id$v=19$"));
    }

    #[tokio::test]
    async fn can_verify_raw_password() {
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

        let hashed_password =
            HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(hashed_password.as_ref(), hash_string.as_str());
        assert!(hashed_password.as_ref().starts_with("$argon2id$v=19$"));

        let result = hashed_password.verify_raw_password(raw_password).await;
        assert!(result.is_ok());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(password)
        }
    }

    #[tokio::test]
    #[quickcheck_macros::quickcheck]
    async fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        HashedPassword::parse(valid_password.0).await.is_ok()
    }
}
