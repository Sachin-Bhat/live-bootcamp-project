CREATE TABLE IF NOT EXISTS two_fa_codes (
    email TEXT NOT NULL PRIMARY KEY,
    login_attempt_id TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
