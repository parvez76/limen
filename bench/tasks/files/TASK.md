# Files

Serves documents from the `data/` directory next to the service.

- `GET /files/{name}` (signed in): answer 200 with `{"name": "...", "content": "<file contents as text>"}`, or 404 if there's no such document.
- `GET /files` (signed in): answer 200 with a JSON array of the document names in `data/`.

Run the service with this directory as its working directory.
