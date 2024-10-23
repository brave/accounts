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
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE verifications (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    token TEXT NOT NULL,
    session_name TEXT,
    verified BOOL NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX ON verifications (email);
