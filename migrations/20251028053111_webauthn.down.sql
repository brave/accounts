DROP TABLE interim_webauthn_registration_states;
DROP TABLE webauthn_credentials;

ALTER TABLE interim_password_states DROP COLUMN webauthn_challenge;

ALTER TABLE interim_password_states DROP COLUMN webauthn_enabled;
ALTER TABLE interim_password_states RENAME COLUMN totp_enabled TO requires_twofa;

ALTER TABLE accounts DROP COLUMN webauthn_enabled_at;
ALTER TABLE accounts DROP COLUMN webauthn_enabled;
ALTER TABLE accounts DROP COLUMN webauthn_id;
