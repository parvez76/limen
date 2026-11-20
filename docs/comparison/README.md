# The README's service comparison

The same JSON service twice: [`service.prvz`](service.prvz) in Parvez, and [`axum/`](axum/) written by hand in Rust with axum, tokio and serde.

Both handle the same cases: `GET /health`, `POST /events` (echo, or 400 `{"error":"count must be >= 0"}`), bad JSON, a missing field, an unknown route (404) and a wrong method (405), all as `{"error": ...}`. Run side by side, they return the same status codes and error format; only the capitalization of the 405 message differs.

| | Parvez | Rust (axum) |
|---|---|---|
| non-blank lines | 9 | 48, plus a 10-line `Cargo.toml` |
| tokens, `tiktoken` `o200k_base` | 76 | 402 |
| tokens, `tiktoken` `cl100k_base` | 76 | 403 |

To check:

```bash
parvez run service.prvz                        # :8080
(cd axum && PORT=8081 cargo run --release)     # :8081
curl -s -X POST localhost:8080/events -d '{"id":"a","kind":"k","count":-1}' -H 'content-type: application/json'
python3 -c "import tiktoken,sys; e=tiktoken.get_encoding('o200k_base'); [print(f, len(e.encode(open(f).read()))) for f in sys.argv[1:]]" service.prvz axum/src/main.rs
```

The Parvez service also gets health and readiness checks, Prometheus metrics, body-size limits, timeouts, backpressure and security headers that the Rust version doesn't have; matching those by hand would make the Rust longer.
