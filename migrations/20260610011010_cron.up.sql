DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'cron') THEN
        PERFORM cron.schedule('remove-old-verifications', '0 0 * * *', $q$DELETE FROM verifications WHERE created_at < CURRENT_TIMESTAMP - interval '24 hours'$q$);
        PERFORM cron.schedule('remove-old-interim-password-states', '0 0 * * *', $q$DELETE FROM interim_password_states WHERE created_at < CURRENT_TIMESTAMP - interval '1 hours'$q$);
        PERFORM cron.schedule('clean-job-history', '0 0 * * *', $q$DELETE FROM cron.job_run_details WHERE end_time < now() - interval '7 days'$q$);
        PERFORM cron.schedule('remove-old-totp-used-codes', '0 0 * * *', $q$DELETE FROM totp_used_codes WHERE created_at < CURRENT_TIMESTAMP - interval '1 hours'$q$);
        PERFORM cron.schedule('delete-unverified-accounts', '0,15,30,45 * * * *', $q$DELETE FROM accounts WHERE last_email_verified_at IS NULL AND created_at < CURRENT_TIMESTAMP - interval '30 minutes'$q$);
    END IF;
END;
$$;
