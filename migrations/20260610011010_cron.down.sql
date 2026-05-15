DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'cron') THEN
        PERFORM cron.unschedule('remove-old-verifications');
        PERFORM cron.unschedule('remove-old-interim-password-states');
        PERFORM cron.unschedule('clean-job-history');
        PERFORM cron.unschedule('remove-old-totp-used-codes');
        PERFORM cron.unschedule('delete-unverified-accounts');
    END IF;
END;
$$;
