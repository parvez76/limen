CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL, token TEXT NOT NULL UNIQUE, is_admin BOOLEAN NOT NULL DEFAULT false);
INSERT INTO users (name, token, is_admin) VALUES ('alice', 'tok-alice', false), ('bob', 'tok-bob', false), ('root', 'tok-admin', true);
