ALTER TABLE accounts ALTER COLUMN last_email_verified_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE accounts ALTER COLUMN last_email_verified_at SET NOT NULL;