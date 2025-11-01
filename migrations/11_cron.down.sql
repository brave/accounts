SELECT cron.unschedule('remove-old-verifications');
SELECT cron.unschedule('remove-old-interim-password-states');
SELECT cron.unschedule('clean-job-history');
SELECT cron.unschedule('remove-old-totp-used-codes');
SELECT cron.unschedule('delete-unverified-accounts');
SELECT cron.unschedule('remove-old-webauthn-registration-states');
