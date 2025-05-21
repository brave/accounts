DROP TABLE IF EXISTS totp_keys; 

ALTER TABLE accounts DROP COLUMN totp_enabled;
ALTER TABLE accounts DROP COLUMN totp_enabled_at;
ALTER TABLE accounts DROP COLUMN recovery_key_hash;
ALTER TABLE accounts DROP COLUMN recovery_key_created_at;

-- Drop columns from interim_password_states table
ALTER TABLE interim_password_states DROP COLUMN requires_twofa;
ALTER TABLE interim_password_states DROP COLUMN awaiting_twofa;
ALTER TABLE interim_password_states DROP COLUMN is_registration;
ALTER TABLE interim_password_states ALTER COLUMN state SET NOT NULL;

ALTER TABLE interim_password_states RENAME TO ake_states;

CREATE TABLE registration_states (
    email TEXT PRIMARY KEY,
    oprf_seed_id INT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE totp_used_codes;