# Tasks: a small multi-user service

A to-do API and page where each signed-in user sees only their own tasks. About 90 lines of code across three files:

| File | What it holds |
|---|---|
| `main.lmn` | the JSON API: list, create (201), mark done, delete (204), and tests |
| `tasks.lmn` | the types, the sign-in guard (`me`) and the shared query |
| `ui/board.msd` | the server-rendered page, guarded the same way |
| `schema.sql` | the Postgres table |

What it shows: Postgres through `sqlx` with bound parameters only; OpenID Connect sign-in for both API clients (bearer tokens) and browsers (encrypted session cookie); ownership enforced inside every query, so another user's task is simply "not found"; JSON errors with stable codes (`invalid_title`, `not_found`, `unauthenticated`); and tests that run without a database.

## Run it

```bash
docker run -d --rm --name tasks-pg -e POSTGRES_PASSWORD=t -e POSTGRES_DB=tasks -p 127.0.0.1:5432:5432 postgres:16-alpine
docker exec -i tasks-pg psql -U postgres -d tasks < schema.sql      # once Postgres is up

limen test main.lmn        # the tests need no database or identity provider

export DATABASE_URL=postgres://postgres:t@127.0.0.1:5432/tasks
export LIMEN_OIDC_ISSUER=https://<your-keycloak>/realms/<realm>    # or Entra ID / Auth0
export LIMEN_OIDC_AUDIENCE=<api-client-id>
export LIMEN_OIDC_CLIENT_ID=<browser-client-id> LIMEN_OIDC_CLIENT_SECRET=<secret>
export LIMEN_PUBLIC_URL=http://localhost:8080 LIMEN_SESSION_KEY=$(openssl rand -hex 32)
limen run main.lmn         # open http://localhost:8080 to sign in
```

Checked end to end against Postgres 16 and Keycloak 26: create, validation, update, delete, the page, and a second user getting 404 for the first user's tasks.
