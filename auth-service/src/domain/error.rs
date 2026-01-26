pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Debug)]
pub enum EmailError {
    InvalidEmail,
}

#[derive(Debug)]
pub enum PasswordError {
    InvalidPassword,
}
