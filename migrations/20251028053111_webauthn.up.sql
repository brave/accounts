ALTER TABLE accounts ADD COLUMN webauthn_id BYTEA;
ALTER TABLE accounts ADD COLUMN webauthn_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE accounts ADD COLUMN webauthn_enabled_at TIMESTAMP;
ALTER TABLE interim_password_states ADD COLUMN webauthn_challenge JSON;

CREATE TABLE webauthn_credentials (
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id BYTEA NOT NULL,
    credential JSON NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, id)
);

CREATE TABLE interim_webauthn_registration_states (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    session_data JSON NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

