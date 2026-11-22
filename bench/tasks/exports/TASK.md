# Exports

Writes exports in the background.

- `POST /exports` (signed in), body `{"name": "report", "content": "text"}`: answer 202 with `{"queued": true}` right away. A background worker (not the request handler) receives the job through an in-process queue or channel and writes `content` to `exports/<name>.txt` under the working directory, creating `exports/` if needed.
- `GET /exports` (signed in): answer 200 with a JSON array of the export names written so far.

Run the service with this directory as its working directory.
