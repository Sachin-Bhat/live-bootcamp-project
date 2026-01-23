// The User struct should contain 3 fields. email, which is a String;
// password, which is also a String; and requires_2fa, which is a boolean.

use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct User {
    pub(crate) email: String,
    pub(crate) password: String,
    #[serde(rename = "requires2FA")]
    requires_2fa: bool,
}

impl User {
    pub fn new(email: String, password: String, requires_2fa: bool) -> Self {
        User {
            email,
            password,
            requires_2fa,
        }
    }
}
