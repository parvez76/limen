# Ping

A DevOps reachability check.

- `POST /ping` (signed in), body `{"host": "example.com"}`: runs the system `ping` once against the host (`ping -c 1 -W 2 <host>`) and answers 200 with `{"host": "...", "reachable": <bool>, "output": "<ping's stdout>"}`. A host that isn't a valid hostname or IP address is a 400.
