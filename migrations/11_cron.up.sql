CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.schedule('remove-old-verifications', '0 0 * * *', $$DELETE FROM verifications WHERE created_at < CURRENT_TIMESTAMP - interval '1 hours'$$);
SELECT cron.schedule('remove-old-interim-password-states', '0 0 * * *', $$DELETE FROM interim_password_states WHERE created_at < CURRENT_TIMESTAMP - interval '1 hours'$$);
SELECT cron.schedule('clean-job-history', '0 0 * * *', $$DELETE 
    FROM cron.job_run_details 
    WHERE end_time < now() - interval '7 days'$$);

SELECT cron.schedule('remove-old-totp-used-codes', '0 0 * * *', $$DELETE FROM totp_used_codes WHERE created_at < CURRENT_TIMESTAMP - interval '1 hours'$$);
SELECT cron.schedule('delete-unverified-accounts', '0/15 * * * *', $$DELETE FROM accounts WHERE last_email_verified_at IS NULL AND created_at < CURRENT_TIMESTAMP - interval '30 minutes'$$);