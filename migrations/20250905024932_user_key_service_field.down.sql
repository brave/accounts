DELETE FROM user_keys;

ALTER TABLE user_keys ADD COLUMN name TEXT NOT NULL;

ALTER TABLE user_keys DROP CONSTRAINT user_keys_pkey;
ALTER TABLE user_keys ADD PRIMARY KEY (account_id, name);

ALTER TABLE user_keys DROP COLUMN IF EXISTS service;
ALTER TABLE user_keys DROP COLUMN IF EXISTS key_name;