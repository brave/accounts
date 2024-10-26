CREATE TABLE oprf_seeds (
    id SERIAL PRIMARY KEY,
    seed BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE accounts ADD COLUMN oprf_seed_id INT REFERENCES oprf_seeds(id);
ALTER TABLE accounts ADD COLUMN opaque_registration BYTEA;

CREATE TABLE ake_states (
    id UUID PRIMARY KEY,
    account_id UUID REFERENCES accounts(id),
    oprf_seed_id INT REFERENCES oprf_seeds(id),
    state BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE registration_states (
    email TEXT PRIMARY KEY,
    oprf_seed_id INT REFERENCES oprf_seeds(id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
