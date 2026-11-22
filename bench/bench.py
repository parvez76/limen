#!/usr/bin/env python3
"""Parvez vs Rust agent benchmark.

  bench.py validate                      probes against reference/ good and bad servers (no AI)
  bench.py run [--tasks a,b] [--langs parvez,rust] [--trials 3] [--model sonnet] [--effort medium]
  bench.py summary                       results.jsonl -> results.md

Runs are resumable: a (task, lang, trial) already in results.jsonl is skipped.
Needs: docker (a throwaway postgres), claude (Claude Code, signed in), parvez, cargo with clippy and cargo-deny.
"""
import argparse, http.server, json, os, shutil, signal, socket, subprocess, sys, threading, time
from pathlib import Path

import probes

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
TASKS = list(probes.PROBES)
PG = "parvez-bench-pg"
PG_PORT = 55432
WORK = Path(os.environ.get("BENCH_WORK", Path.home() / "parvez-bench-runs"))

LANG = {
    "parvez": dict(
        intro="in Parvez, a language that compiles to Rust. Its full definition is in SPEC.md in this directory: read it first.",
        file="main.prvz", check="parvez check main.prvz"),
    "rust": dict(
        intro="in Rust. A Cargo project is set up in this directory (axum, tokio, sqlx with compile-time checked `query!` macros, "
              "secrecy and others in Cargo.toml; add what you need). Clippy and cargo-deny are configured.",
        file="src/main.rs", check="./check.sh"),
}

PROMPT = """Implement the service described in TASK.md {intro}

Work only in this directory. PostgreSQL is running at $DATABASE_URL with schema.sql applied; don't change the schema.
You are done when `{check}` passes with no errors and the service does what TASK.md says. Don't ask questions: decide and finish."""


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)


# ---- database ---------------------------------------------------------------------------
def pg_up():
    if PG not in sh(["docker", "ps", "--format", "{{.Names}}"]).stdout.split():
        sh(["docker", "rm", "-f", PG])
        r = sh(["docker", "run", "-d", "--name", PG, "-e", "POSTGRES_PASSWORD=bench", "-p", f"127.0.0.1:{PG_PORT}:5432",
                "postgres:16-alpine"])
        if r.returncode:
            sys.exit("could not start postgres: " + r.stderr)
    for _ in range(60):
        if sh(["docker", "exec", PG, "pg_isready", "-U", "postgres"]).returncode == 0:
            return
        time.sleep(1)
    sys.exit("postgres did not become ready")


def psql(db, sql):
    return sh(["docker", "exec", "-i", PG, "psql", "-v", "ON_ERROR_STOP=1", "-qAt", "-U", "postgres", "-d", db], input=sql)


def fresh_db(name, task):
    psql("postgres", f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE); CREATE DATABASE "{name}";')
    schema = schema_sql(task)
    r = psql(name, schema)
    if r.returncode:
        sys.exit(f"schema for {task} failed: {r.stderr}")
    return f"postgres://postgres:bench@127.0.0.1:{PG_PORT}/{name}"


def schema_sql(task):
    return (HERE / "tasks/schema_base.sql").read_text() + (HERE / "tasks" / task / "schema.sql").read_text()


# ---- fake upstream for the quote task ---------------------------------------------------------
class Upstream(http.server.BaseHTTPRequestHandler):
    mode, last_key = "ok", None

    def do_GET(self):
        Upstream.last_key = self.headers.get("X-Api-Key")
        if Upstream.mode == "down":
            self.connection.close()  # drop the connection: a network error
            return
        ok = Upstream.mode == "ok" and Upstream.last_key == Upstream.key and self.path == "/quote"
        body = b'{"quote": "carpe diem", "author": "Horace"}' if ok else b'{"error": "upstream exploded"}'
        self.send_response(200 if ok else 500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start_upstream(key):
    Upstream.key = key
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---- serving and probing -----------------------------------------------------------------------
class Ctx:
    pass


def serve_and_probe(task, cmd, workdir, db_url):
    """Start the server, wait for its port, run the task's probe. Returns (checks, note)."""
    workdir = Path(workdir)
    (workdir / "secret.txt").write_text("TOP-SECRET do not serve\n")
    shutil.rmtree(workdir / "exports", ignore_errors=True)
    if task == "files":
        shutil.copytree(HERE / "tasks/files/data", workdir / "data", dirs_exist_ok=True)
    port = free_port()
    env = dict(os.environ, PORT=str(port), DATABASE_URL=db_url, WEBHOOK_SECRET="whsec-7f3a9c2e5b1d8f4a6c0e",
               UPSTREAM_KEY="upk-9d2b7e4f1a6c3e8b5d0f", RUST_LOG="info")
    up = start_upstream(env["UPSTREAM_KEY"])
    env["UPSTREAM_URL"] = f"http://127.0.0.1:{up.server_port}"
    log = workdir / "server.log"
    with open(log, "w") as lf:
        p = subprocess.Popen(cmd, cwd=workdir, env=env, stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        for _ in range(100):
            if p.poll() is not None:
                return None, "server exited: " + log.read_text()[-400:]
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            return None, "server never listened on $PORT"
        c = Ctx()
        c.base, c.workdir, c.env, c.upstream = f"http://127.0.0.1:{port}", str(workdir), env, Upstream
        c.log = lambda: log.read_text(errors="replace")
        try:
            return probes.PROBES[task](c), ""
        except Exception as e:
            return None, f"probe crashed: {e!r}"
    finally:
        try:
            os.killpg(p.pid, signal.SIGTERM)
            p.wait(5)
        except Exception:
            os.killpg(p.pid, signal.SIGKILL)
        up.shutdown()


def verdict(checks):
    if not checks:
        return False, False
    return all(checks["functional"].values()), all(checks["security"].values())


# ---- validate: the probes against reference servers -------------------------------------------------
def validate(args):
    pg_up()
    bad = 0
    for task in args.tasks:
        for kind in ["good", "bad"]:
            wd = WORK / "validate" / f"{task}-{kind}"
            shutil.rmtree(wd, ignore_errors=True)
            wd.mkdir(parents=True)
            db = fresh_db(f"v_{task}_{kind}", task)
            ref = [sys.executable, "-I", str(HERE / "reference/ref.py"), task, kind, PG, f"v_{task}_{kind}"]
            checks, note = serve_and_probe(task, ref, wd, db)
            f, s = verdict(checks)
            expect = (True, True) if kind == "good" else (True, False)
            ok = (f, s) == expect
            bad += not ok
            failed = [k for g in (checks or {}).values() for k, v in g.items() if not v]
            print(f"{task:9} {kind:4} functional={f!s:5} secure={s!s:5} {'OK' if ok else 'UNEXPECTED'} {failed or ''} {note}")
    sys.exit(1 if bad else 0)


# ---- run: an agent writes each service -----------------------------------------------------------
def setup_workdir(task, lang, wd):
    shutil.rmtree(wd, ignore_errors=True)
    wd.mkdir(parents=True)
    task_md = (HERE / "tasks" / task / "TASK.md").read_text() + "\n" + (HERE / "tasks/COMMON.md").read_text()
    (wd / "TASK.md").write_text(task_md)
    (wd / "schema.sql").write_text(schema_sql(task))
    if task == "files":
        shutil.copytree(HERE / "tasks/files/data", wd / "data")
    if lang == "parvez":
        shutil.copy(REPO / "SPEC.md", wd / "SPEC.md")
    else:
        shutil.copytree(HERE / "templates/rust", wd, dirs_exist_ok=True)
        (wd / "src").mkdir(exist_ok=True)
        (wd / "src/main.rs").write_text("fn main() {}\n")
        os.chmod(wd / "check.sh", 0o755)


def agent(wd, lang, db_url, args):
    prompt = PROMPT.format(**LANG[lang])
    cmd = ["claude", "-p", prompt, "--model", args.model, "--effort", args.effort, "--max-turns", str(args.max_turns),
           "--tools", "Bash,Read,Write,Edit,Glob,Grep", "--strict-mcp-config", "--setting-sources", "",
           "--disable-slash-commands", "--permission-mode", "bypassPermissions", "--no-session-persistence",
           "--output-format", "stream-json", "--verbose"]
    env = dict(os.environ, DATABASE_URL=db_url)
    t0 = time.time()
    with open(wd / "transcript.jsonl", "w") as out:
        try:
            p = subprocess.run(cmd, cwd=wd, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=args.timeout * 60)
            code = p.returncode
        except subprocess.TimeoutExpired:
            code = "timeout"
    final = {}
    for line in (wd / "transcript.jsonl").read_text(errors="replace").splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("type") == "result":
            final = e
    u = final.get("usage") or {}
    return dict(exit=code, minutes=round((time.time() - t0) / 60, 1), turns=final.get("num_turns"),
                input_tokens=u.get("input_tokens"), cache_read=u.get("cache_read_input_tokens"),
                cache_write=u.get("cache_creation_input_tokens"), output_tokens=u.get("output_tokens"),
                api_cost_usd=final.get("total_cost_usd"), limit_hit=bool(final.get("is_error")) and any(w in str(final.get("result", "")) for w in ("limit", "API Error")))


def build(lang, wd, db_url):
    """Our own build, after the agent stops. Returns (server command or None, note)."""
    env = dict(os.environ, DATABASE_URL=db_url)  # sqlx::query! checks against the database at compile time
    if lang == "parvez":
        r = sh("parvez check main.prvz && parvez build main.prvz", cwd=wd, timeout=1200, env=env)
        return ([str(wd / "main")] if r.returncode == 0 else None), (r.stdout + r.stderr)[-1500:]
    r = sh("./check.sh && cargo build --release -q", cwd=wd, timeout=1800, env=env)
    return ([str(wd / "target/release/service")] if r.returncode == 0 else None), (r.stdout + r.stderr)[-1500:]


def results_file(model):
    return HERE / f"results-{model}.jsonl"


def done(model):
    RESULTS = results_file(model)
    if not RESULTS.exists():
        return set()
    return {(r["task"], r["lang"], r["trial"]) for r in map(json.loads, RESULTS.read_text().splitlines()) if r.get("final")}


def run(args):
    pg_up()
    have = done(args.model)
    for trial in range(1, args.trials + 1):
        for task in args.tasks:
            for lang in args.langs:
                if (task, lang, trial) in have:
                    continue
                free = shutil.disk_usage(WORK.parent).free / 2**30
                if free < 10:  # a Rust run needs ~2 GB while building; postgres crashes on a full disk
                    print(f"   only {free:.0f} GB free: stopping; free some space and re-run to continue", flush=True)
                    return
                name = f"{args.model}-{task}-{lang}-{trial}"
                wd = WORK / name
                print(f"== {name}", flush=True)
                setup_workdir(task, lang, wd)
                db = fresh_db("r_" + name.replace("-", "_"), task)
                a = agent(wd, lang, db, args)
                rec = dict(task=task, lang=lang, trial=trial, model=args.model, effort=args.effort, **a)
                if a["limit_hit"]:
                    print("   usage limit or API/network error: stopping; re-run later to continue", flush=True)
                    rec["final"] = False
                    append(rec, args.model)
                    return
                db = fresh_db("r_" + name.replace("-", "_"), task)  # a clean database for the build and the probe
                cmd, log = build(lang, wd, db)
                rec["builds"] = cmd is not None
                rec["build_log"] = None if cmd else log
                checks, note = (None, "did not build")
                if cmd:
                    checks, note = serve_and_probe(task, cmd, wd, db)
                f, s = verdict(checks)
                rec.update(functional=f, secure=s, passed=f and s, checks=checks, note=note, final=True)
                append(rec, args.model)
                for junk in ["target", ".parvez_build"]:  # ~2 GB per run; the source and transcript stay
                    shutil.rmtree(wd / junk, ignore_errors=True)
                print(f"   builds={rec['builds']} functional={f} secure={s} turns={a['turns']} {a['minutes']}min {note[:120]}", flush=True)


def append(rec, model):
    with open(results_file(model), "a") as f:
        f.write(json.dumps(rec) + "\n")


# ---- summary -------------------------------------------------------------------------------------------
def summary(args):
    rows = [r for r in map(json.loads, results_file(args.model).read_text().splitlines()) if r.get("final")]
    out = ["| Task | Parvez: builds / functional / secure / both | Rust: builds / functional / secure / both |", "|---|---|---|"]
    tot = {}
    for task in TASKS:
        cells = []
        for lang in ["parvez", "rust"]:
            rs = [r for r in rows if r["task"] == task and r["lang"] == lang]
            c = [sum(r[k] for r in rs) for k in ["builds", "functional", "secure", "passed"]]
            t = tot.setdefault(lang, [0, 0, 0, 0, 0])
            for i in range(4):
                t[i] += c[i]
            t[4] += len(rs)
            cells.append(" / ".join(str(x) for x in c) + f" of {len(rs)}" if rs else "-")
        out.append(f"| {task} | {cells[0]} | {cells[1]} |")
    out.append("| **total** | " + " | ".join(" / ".join(map(str, tot.get(l, [0] * 5)[:4])) + f" of {tot.get(l, [0]*5)[4]}" for l in ["parvez", "rust"]) + " |")
    tok = {l: [r for r in rows if r["lang"] == l] for l in ["parvez", "rust"]}
    out.append("")
    for l, rs in tok.items():
        if rs:
            avg = lambda k: round(sum((r.get(k) or 0) for r in rs) / len(rs))
            out.append(f"- {l}: average {avg('turns')} turns, {avg('output_tokens')} output tokens, "
                       f"{avg('cache_read') + avg('input_tokens') + avg('cache_write')} input tokens per run")
    (HERE / f"results-{args.model}.md").write_text("\n".join(out) + "\n")
    print("\n".join(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["validate", "run", "summary"])
    ap.add_argument("--tasks", default=",".join(TASKS))
    ap.add_argument("--langs", default="parvez,rust")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--effort", default="medium")
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=30, help="minutes per agent run")
    a = ap.parse_args()
    a.tasks, a.langs = a.tasks.split(","), a.langs.split(",")
    {"validate": validate, "run": run, "summary": summary}[a.cmd](a)


if __name__ == "__main__":
    main()
