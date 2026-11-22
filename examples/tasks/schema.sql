CREATE TABLE IF NOT EXISTS tasks (
    id         BIGSERIAL PRIMARY KEY,
    owner      TEXT NOT NULL,          -- the user's `sub` claim
    title      TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    done       BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tasks_owner ON tasks (owner, id);
