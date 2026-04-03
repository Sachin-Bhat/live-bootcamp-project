// The User struct should contain 3 fields. email, which is a String;
// password, which is also a String; and requires_2fa, which is a boolean.

use crate::domain::{Email, HashedPassword};
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct User {
    pub(crate) email: Email,
    pub(crate) password: HashedPassword,
    #[serde(rename = "requires2FA")]
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
