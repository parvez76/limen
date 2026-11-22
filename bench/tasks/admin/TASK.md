# Admin

User administration.

- `GET /health`: answer 200 with `{"ok": true}`. Used by the load balancer, no sign-in.
- `GET /users`: answer 200 with a JSON array of users, each `{"id", "name", "is_admin"}` (never the token).
- `DELETE /users/{id}`: deletes the user, answer 204; 404 if there's no such user.
- `GET /me` (signed in): answer 200 with the caller as `{"id", "name", "is_admin"}`.

Only administrators manage users.
