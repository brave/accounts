CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.schedule('remove-old-verifications', '0 0 * * *', $$DELETE FROM verifications WHERE created_at < CURRENT_TIMESTAMP - interval '1 hours'$$);
SELECT cron.schedule('remove-old-ake-states', '0 0 * * *', $$DELETE FROM ake_states WHERE created_at < CURRENT_TIMESTAMP - interval '1 hours'$$);
SELECT cron.schedule('remove-old-registration-states', '0 0 * * *', $$DELETE FROM registration_states WHERE created_at < CURRENT_TIMESTAMP - interval '1 hours'$$);
SELECT cron.schedule('clean-job-history', '0 0 * * *', $$DELETE 
    FROM cron.job_run_details 
    WHERE end_time < now() - interval '7 days'$$);
