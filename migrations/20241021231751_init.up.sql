CREATE TABLE oprf_seeds (
    id SERIAL PRIMARY KEY,
    seed BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    oprf_seed_id INT REFERENCES oprf_seeds(id),
    opaque_registration BYTEA,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(email)
);

CREATE TABLE ake_states (
    id UUID PRIMARY KEY,
    account_id UUID REFERENCES accounts(id),
    oprf_seed_id INT REFERENCES oprf_seeds(id),
    state BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE registration_states (
    email TEXT PRIMARY KEY,
    oprf_seed_id INT REFERENCES oprf_seeds(id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
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
