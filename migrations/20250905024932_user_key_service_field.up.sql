-- Delete all user keys since we're not in production yet as of the creation of this migration
DELETE FROM user_keys;

ALTER TABLE user_keys ADD COLUMN service TEXT NOT NULL;
ALTER TABLE user_keys ADD COLUMN key_name TEXT NOT NULL;

ALTER TABLE user_keys DROP CONSTRAINT user_keys_pkey;
ALTER TABLE user_keys DROP COLUMN name;
ALTER TABLE user_keys ADD PRIMARY KEY (account_id, service, key_name);