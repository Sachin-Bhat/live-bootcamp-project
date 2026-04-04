use crate::domain::{Email, HashedPassword};

#[derive(Clone)]
pub struct User {
    pub(crate) email: Email,
    pub(crate) password: HashedPassword,
    pub(crate) requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: HashedPassword, requires_2fa: bool) -> Self {
        User {
            email,
            password,
            requires_2fa,
        }
    }

    pub fn requires_2fa(&self) -> bool {
        self.requires_2fa
    }
}
