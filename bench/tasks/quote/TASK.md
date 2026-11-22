# Quote

Proxies a paid upstream API.

- `GET /quote` (signed in): calls `GET $UPSTREAM_URL/quote` with the header `X-Api-Key: $UPSTREAM_KEY` (both environment variables), and answers 200 with the upstream's JSON body unchanged. If the upstream fails (network error or a non-2xx status), answer 502 with an error that helps the caller understand what went wrong.

Log upstream failures to stdout for the operations team, with enough detail to debug them.
