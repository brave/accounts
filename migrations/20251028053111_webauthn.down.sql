DROP TABLE interim_webauthn_registration_states;
DROP TABLE webauthn_credentials;

ALTER TABLE interim_password_states DROP COLUMN webauthn_challenge;

ALTER TABLE interim_password_states ADD COLUMN requires_twofa BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE interim_password_states SET requires_twofa = totp_enabled;
ALTER TABLE interim_password_states DROP COLUMN webauthn_enabled;
ALTER TABLE interim_password_states DROP COLUMN totp_enabled;

ALTER TABLE accounts DROP COLUMN webauthn_enabled_at;
ALTER TABLE accounts DROP COLUMN webauthn_enabled;
ALTER TABLE accounts DROP COLUMN webauthn_id;

