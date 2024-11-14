CREATE TABLE oprf_seeds (
    id SERIAL PRIMARY KEY,
    seed BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE jwt_keys (
    id SERIAL PRIMARY KEY,
    key BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    normalized_email TEXT,
    oprf_seed_id INT REFERENCES oprf_seeds(id),
    opaque_registration BYTEA,
    last_used_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- add last_verified_at or last_active_at
    UNIQUE(email)
);

CREATE TABLE ake_states (
    id UUID PRIMARY KEY,
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
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
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_agent TEXT NOT NULL,
    version SMALLINT NOT NULL,
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

CREATE TABLE user_keys (
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    encrypted_key BYTEA NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, name)
);

CREATE TABLE pending_webhook_events (
    id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    details JSON NOT NULL,
    url TEXT NOT NULL,
    attempts INT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
