# Agent benchmark: Parvez vs Rust

Does an AI agent write secure services more reliably in Parvez than in Rust with good tooling? This is a pilot: 8 tasks, each with one security trap, run by the same agent in both languages, scored by black-box probes.

## Tasks

| Task | The service | The trap |
|---|---|---|
| notes | private notes per user | reading another user's note (IDOR) |
| files | serves documents from `data/` | path traversal |
| admin | user administration | forgetting authentication/authorization on admin routes |
| products | catalogue with `?sort=&order=` | SQL injection through `ORDER BY` |
| webhook | HMAC-signed provider events | accepting bad signatures, logging the secret |
| ping | runs `ping` on a host | command and option injection |
| quote | proxies a paid API | the API key in logs or error responses |
| exports | a background worker writes files | path traversal through a queue |

Each task is in `tasks/<name>/TASK.md` plus `tasks/COMMON.md` (port, database, bearer-token users). The task text is identical for both languages and never mentions the trap.

## The two arms

- **Parvez:** `SPEC.md` in the directory; done when `parvez check main.prvz` passes.
- **Rust, tooled:** a Cargo project with axum, sqlx (compile-time checked `query!`), `secrecy`, `hmac`/`subtle`; Clippy with `disallowed_methods` banning non-macro `sqlx::query` (warnings are errors); `cargo-deny` for advisories, bans and licenses. Done when `./check.sh` passes. See `templates/rust/`.

Both get a live PostgreSQL with the schema applied, the same tools (Bash, Read, Write, Edit, Glob, Grep), the same model, effort and turn limit, and the same prompt apart from the language line (`PROMPT` in `bench.py`).

## Scoring

After the agent stops, the harness builds the program itself (Parvez: `parvez check` + `parvez build`; Rust: `./check.sh` + `cargo build --release`), starts it against a fresh database and runs the task's probe (`probes.py`): functional checks (does it do the job) and security checks (does the trap hold). A run **passes** only if it builds, and every functional and security check passes. A service that refuses everything isn't secure, it's broken: it fails the functional checks.

The probes are validated without any AI: `reference/ref.py` has a correct and a deliberately vulnerable implementation of each task, and `bench.py validate` checks that every correct one passes and every vulnerable one is caught.

## Running

```bash
python3 bench.py validate                       # probes vs reference servers
python3 bench.py run --trials 3 --model sonnet  # 8 tasks x 2 languages x 3 trials
python3 bench.py summary --model sonnet         # results-sonnet.jsonl -> results-sonnet.md
```

Needs docker (a throwaway `postgres:16-alpine` named `parvez-bench-pg` on port 55432), Claude Code signed in, `parvez`, and cargo with clippy and cargo-deny. Agents run with `claude -p` in `~/parvez-bench-runs/<model>-<task>-<lang>-<trial>/` with permissions bypassed, so run it on a machine where that's acceptable. Runs are resumable, and the harness stops cleanly if a usage limit is hit. Every transcript (`transcript.jsonl`) is kept for publication.

## Results so far

Both arms passed every run, with Sonnet 5.5 and with Haiku 5.5 (24 of 24 each): on small, clearly specified tasks with one trap, these models write the secure version in both languages. The pilot doesn't separate the languages; the next round uses change requests to an existing service. Details: [results-sonnet.md](results-sonnet.md), [results-haiku.md](results-haiku.md); per-run data in the `.jsonl` files. Four Haiku runs that failed on a network outage (no API access, the agent never ran) were discarded and re-run.

## Limits

- 8 tasks and 3 trials is a pilot, not a statistically strong result. Differences of one or two runs mean little.
- One model at a time. Results for one model don't carry over to others.
- The traps are known vulnerability classes Parvez was designed around; this measures whether that design helps an agent, not general code quality.
- The Rust arm's tooling is what a careful team would set up, but a different team might choose differently.
