ALTER TABLE verifications ADD COLUMN new_session_id UUID;
CREATE INDEX idx_verifications_new_session_id_hash ON verifications USING HASH (new_session_id);
