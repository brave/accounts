CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(email)
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    session_name TEXT,
    version SMALLINT NOT NULL,
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE verifications (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    service TEXT NOT NULL,
    intent TEXT NOT NULL,
    verified BOOL NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX ON verifications (email);
