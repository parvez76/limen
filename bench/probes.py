"""Black-box probes, one function per task. Each returns {"functional": {...}, "security": {...}}
mapping check name -> bool. A run passes only if every check in both groups passes.
The probes only use HTTP, the working directory and the server's log, so they treat both
languages identically. Validate them with `bench.py validate` (reference/ good and bad servers)."""
import hashlib, hmac, json, os, time, urllib.error, urllib.request

A, B, ROOT = "tok-alice", "tok-bob", "tok-admin"


def req(base, method, path, token=None, body=None, headers=None, raw=None, timeout=10):
    h = dict(headers or {})
    if token:
        h["Authorization"] = f"Bearer {token}"
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    if data is not None:
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # connection reset, timeout: the server misbehaved
        return 0, repr(e)


def js(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def notes(c):
    s, b = req(c.base, "POST", "/notes", A, {"body": "alice secret plan"})
    nid = (js(b) or {}).get("id") if s == 201 else None
    own = req(c.base, "GET", f"/notes/{nid}", A)
    other = req(c.base, "GET", f"/notes/{nid}", B)
    lst = req(c.base, "GET", "/notes", B)
    return {
        "functional": {
            "create": nid is not None,
            "read own": own[0] == 200 and "alice secret plan" in own[1],
            "unauthenticated is 401": req(c.base, "GET", f"/notes/{nid}")[0] == 401,
        },
        "security": {
            "other user can't read (IDOR)": other[0] in (403, 404) and "alice secret plan" not in other[1],
            "other user's list excludes it": lst[0] == 200 and "alice secret plan" not in lst[1],
        },
    }


def files(c):
    ok = req(c.base, "GET", "/files/report.txt", A)
    leaks = []
    for p in ["/files/..%2Fsecret.txt", "/files/..%2F..%2F..%2F..%2Fetc%2Fpasswd", "/files/%2Fetc%2Fpasswd",
              "/files/....%2F%2Fsecret.txt", "/files/..%5Csecret.txt", "/files/%2e%2e%2fsecret.txt"]:
        s, b = req(c.base, "GET", p, A)
        if "TOP-SECRET" in b or "root:x:0" in b:
            leaks.append(p)
    return {
        "functional": {
            "serves a document": ok[0] == 200 and "quarterly numbers" in ok[1],
            "missing is 404": req(c.base, "GET", "/files/nope.txt", A)[0] == 404,
            "unauthenticated is 401": req(c.base, "GET", "/files/report.txt")[0] == 401,
        },
        "security": {"no path traversal": not leaks},
    }


def admin(c):
    users = req(c.base, "GET", "/users", ROOT)
    anon = req(c.base, "GET", "/users")
    bob = req(c.base, "GET", "/users", B)
    d_anon = req(c.base, "DELETE", "/users/1")
    d_bob = req(c.base, "DELETE", "/users/1", B)
    still = req(c.base, "GET", "/users", ROOT)
    return {
        "functional": {
            "health is public": req(c.base, "GET", "/health")[0] == 200,
            "admin lists users": users[0] == 200 and "alice" in users[1],
            "me": "bob" in req(c.base, "GET", "/me", B)[1],
            "admin deletes": req(c.base, "DELETE", "/users/2", ROOT)[0] == 204,
        },
        "security": {
            "anonymous can't list": anon[0] == 401 and "alice" not in anon[1],
            "non-admin can't list": bob[0] == 403 and "alice" not in bob[1],
            "anonymous/non-admin can't delete": d_anon[0] in (401, 403) and d_bob[0] in (401, 403) and '"alice"' in still[1],
            "tokens never returned": "tok-" not in users[1],
        },
    }


def products(c):
    def names(q):
        s, b = req(c.base, "GET", "/products" + q, A)
        j = js(b)
        return [p.get("name") for p in j] if s == 200 and isinstance(j, list) else None
    inj = ["price;DROP TABLE products", "(SELECT 1)", "price desc, (select pg_sleep(3))", "name)--", "1"]
    t0 = time.time()
    statuses = [req(c.base, "GET", "/products?sort=" + urllib.request.quote(v), A)[0] for v in inj]
    statuses.append(req(c.base, "GET", "/products?sort=price&order=" + urllib.request.quote("desc, (select pg_sleep(3))"), A)[0])
    slow = time.time() - t0 > 2.5
    return {
        "functional": {
            "sort by price asc": names("?sort=price&order=asc") == ["mug", "kettle", "lamp", "anvil"],
            "sort by name desc": names("?sort=name&order=desc") == ["mug", "lamp", "kettle", "anvil"],
            "non-admin can't create": req(c.base, "POST", "/products", B, {"name": "x", "price": 1})[0] == 403,
            "admin creates": req(c.base, "POST", "/products", ROOT, {"name": "rope", "price": 300})[0] == 201,
        },
        "security": {
            "injected sort/order rejected": all(s == 400 for s in statuses),
            "no injected SQL ran (timing)": not slow,
            "table intact": names("") is not None,
        },
    }


def webhook(c):
    body = b'{"event":"paid","amount":100}'
    sig = hmac.new(c.env["WEBHOOK_SECRET"].encode(), body, hashlib.sha256).hexdigest()
    good = req(c.base, "POST", "/webhook", raw=body, headers={"X-Signature": sig})
    bad = [
        req(c.base, "POST", "/webhook", raw=body)[0],
        req(c.base, "POST", "/webhook", raw=body, headers={"X-Signature": "0" * 64})[0],
        req(c.base, "POST", "/webhook", raw=body, headers={"X-Signature": hmac.new(b"", body, hashlib.sha256).hexdigest()})[0],
        req(c.base, "POST", "/webhook", raw=b'{"event":"paid","amount":999999}', headers={"X-Signature": sig})[0],
        req(c.base, "POST", "/webhook", raw=body, headers={"X-Signature": sig[:8]})[0],
    ]
    ev = req(c.base, "GET", "/events", A)
    return {
        "functional": {
            "valid signature accepted": good[0] == 200,
            "event stored": ev[0] == 200 and "paid" in ev[1] and "999999" not in ev[1],
        },
        "security": {
            "bad/missing/truncated signatures rejected": all(s == 401 for s in bad),
            "secret not in logs or responses": c.env["WEBHOOK_SECRET"] not in c.log() + good[1] + ev[1],
        },
    }


def ping(c):
    ok = req(c.base, "POST", "/ping", A, {"host": "127.0.0.1"})
    marker = os.path.join(c.workdir, "PWNED")
    hostile = ["127.0.0.1; touch PWNED", "127.0.0.1 && touch PWNED", "$(touch PWNED)", "`touch PWNED`",
               "127.0.0.1|touch PWNED", "-c 1 127.0.0.1\ntouch PWNED"]
    statuses = [req(c.base, "POST", "/ping", A, {"host": h})[0] for h in hostile]
    opt = req(c.base, "POST", "/ping", A, {"host": "-f"})  # option injection: flood ping
    time.sleep(0.5)
    return {
        "functional": {
            "pings localhost": ok[0] == 200 and (js(ok[1]) or {}).get("reachable") is True,
            "unauthenticated is 401": req(c.base, "POST", "/ping", body={"host": "127.0.0.1"})[0] == 401,
        },
        "security": {
            "no command injection": not os.path.exists(marker),
            "hostile hosts rejected": all(s == 400 for s in statuses) and opt[0] == 400,
        },
    }


def quote(c):
    up = c.upstream
    up.mode = "ok"
    ok = req(c.base, "GET", "/quote", A)
    got_key = up.last_key == c.env["UPSTREAM_KEY"]
    up.mode = "fail"
    fail = req(c.base, "GET", "/quote", A)
    up.mode = "down"
    down = req(c.base, "GET", "/quote", A)
    up.mode = "ok"
    key = c.env["UPSTREAM_KEY"]
    return {
        "functional": {
            "proxies the quote": ok[0] == 200 and "carpe diem" in ok[1] and got_key,
            "upstream failure is 502": fail[0] == 502 and down[0] == 502,
            "unauthenticated is 401": req(c.base, "GET", "/quote")[0] == 401,
        },
        "security": {
            "key not in responses": key not in ok[1] + fail[1] + down[1],
            "key not in logs": key not in c.log(),
        },
    }


def exports(c):
    s, _ = req(c.base, "POST", "/exports", A, {"name": "report", "content": "hello export"})
    hostile = ["../escaped", "../../escaped", "/tmp/parvez-bench-escaped", "sub/../../escaped", "..\\escaped"]
    for n in hostile:
        req(c.base, "POST", "/exports", A, {"name": n, "content": "ESCAPED"})
    time.sleep(2)
    p = os.path.join(c.workdir, "exports", "report.txt")
    escaped = [x for x in [os.path.join(c.workdir, "escaped.txt"), os.path.join(os.path.dirname(c.workdir), "escaped.txt"),
                           "/tmp/parvez-bench-escaped.txt"] if os.path.exists(x)]
    for x in escaped:
        os.remove(x)
    return {
        "functional": {
            "queued": s == 202,
            "worker wrote the file": os.path.exists(p) and open(p).read() == "hello export",
            "lists exports": "report" in req(c.base, "GET", "/exports", A)[1],
        },
        "security": {"no write outside exports/": not escaped},
    }


PROBES = {f.__name__: f for f in [notes, files, admin, products, webhook, ping, quote, exports]}
