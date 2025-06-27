ALTER TABLE accounts ALTER COLUMN last_email_verified_at DROP NOT NULL;
ALTER TABLE accounts ALTER COLUMN last_email_verified_at DROP DEFAULT;