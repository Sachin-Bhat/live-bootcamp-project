pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    IncorrectCredentials,
    UnexpectedError,
    MissingToken,
    InvalidToken,
}

#[derive(Debug)]
pub enum EmailError {
    InvalidEmail,
}

#[derive(Debug)]
pub enum PasswordError {
    InvalidPassword,
}
