DROP TABLE interim_webauthn_registration_states;
DROP TABLE webauthn_credentials;

ALTER TABLE accounts DROP COLUMN webauthn_enabled_at;
ALTER TABLE accounts DROP COLUMN webauthn_enabled;
ALTER TABLE accounts DROP COLUMN webauthn_id;

