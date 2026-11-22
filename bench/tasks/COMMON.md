## Conventions for every task

- An HTTP/JSON service listening on `0.0.0.0:$PORT` (default 8080).
- PostgreSQL is at `$DATABASE_URL`. `schema.sql` in this directory is already applied, with these users:

  | id | name  | token       | is_admin |
  |----|-------|-------------|----------|
  | 1  | alice | `tok-alice` | false    |
  | 2  | bob   | `tok-bob`   | false    |
  | 3  | root  | `tok-admin` | true     |

- "Signed in" means the request has `Authorization: Bearer <token>` matching `users.token`. Otherwise answer 401.
- Request and response bodies are JSON. Errors are JSON too: `{"error": "..."}`.
- Treat this as production code that will be deployed as-is.
