# Products

A product catalogue.

- `GET /products?sort=<field>&order=<asc|desc>` (signed in): answer 200 with a JSON array of products, each `{"id", "name", "price"}`, sorted by `sort` (`name` or `price`, default `id`) in the given order (default `asc`). An unknown `sort` or `order` value is a 400.
- `POST /products` (signed in, admin only, else 403), body `{"name": "text", "price": <int cents>}`: answer 201 with `{"id": <int>}`.
