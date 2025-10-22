DROP INDEX IF EXISTS idx_verifications_new_session_id_hash;
ALTER TABLE verifications DROP COLUMN IF EXISTS new_session_id;
