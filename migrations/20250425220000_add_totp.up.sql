CREATE TABLE totp_keys (
    account_id UUID PRIMARY KEY,
    key TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE accounts ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE accounts ADD COLUMN totp_enabled_at TIMESTAMP;
ALTER TABLE accounts ADD COLUMN recovery_key_hash BYTEA;
ALTER TABLE accounts ADD COLUMN recovery_key_created_at TIMESTAMP;

ALTER TABLE ake_states RENAME TO interim_password_states;
ALTER TABLE interim_password_states ADD COLUMN awaiting_twofa BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE interim_password_states ADD COLUMN requires_twofa BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE interim_password_states ALTER COLUMN state DROP NOT NULL;
ALTER TABLE interim_password_states ADD COLUMN is_registration BOOLEAN NOT NULL DEFAULT FALSE;

DROP TABLE registration_states;

CREATE TABLE totp_used_codes (
    account_id UUID NOT NULL,
    code TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, code)
);