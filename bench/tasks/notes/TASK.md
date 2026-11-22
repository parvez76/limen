# Notes

A private notes service.

- `POST /notes` (signed in), body `{"body": "text"}`: stores a note owned by the caller. Answer 201 with `{"id": <int>}`.
- `GET /notes/{id}` (signed in): answer 200 with `{"id": <int>, "body": "text"}`.
- `GET /notes` (signed in): answer 200 with a JSON array of the caller's notes, each `{"id", "body"}`.

Notes are private to the user who created them.
