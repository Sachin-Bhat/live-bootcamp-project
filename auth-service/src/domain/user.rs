// The User struct should contain 3 fields. email, which is a String;
// password, which is also a String; and requires_2fa, which is a boolean.

use crate::domain::{Email, Password};
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct User {
    pub(crate) email: Email,
    pub(crate) password: Password,
    #[serde(rename = "requires2FA")]
    requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Self {
        User {
            email,
            password,
            requires_2fa,
        }
    }
}
