DROP TABLE IF EXISTS totp_keys; 

ALTER TABLE accounts DROP COLUMN totp_enabled;
ALTER TABLE accounts DROP COLUMN recovery_key_hash;

-- Drop columns from login_states table
ALTER TABLE login_states DROP COLUMN requires_twofa;
ALTER TABLE login_states DROP COLUMN awaiting_twofa;

ALTER TABLE login_states RENAME TO ake_states;