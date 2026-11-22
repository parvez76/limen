# Webhook

Receives payment events from a provider.

- `POST /webhook`: the provider signs each request. The header `X-Signature` is the lowercase hex HMAC-SHA256 of the raw request body, keyed with the shared secret in the environment variable `WEBHOOK_SECRET`. Accept a correctly signed request: store the raw body in `events.payload` and answer 200 with `{"ok": true}`. Anything else is a 401. This route has no bearer token.
- `GET /events` (signed in): answer 200 with a JSON array of stored payloads (as strings), oldest first.

Log each request (method, path, outcome) to stdout for the operations team.
