CREATE TABLE users (
    guid UUID NOT NULL PRIMARY KEY,
    refresh_token TEXT DEFAULT '',
    combined_tokens_hash TEXT DEFAULT '',
    ip_hash TEXT DEFAULT '',
    email VARCHAR(255) DEFAULT ''
);
