# Roadmap

Ideas, not promises. There are no dates: things get built when they're interesting to build. Each idea lists its prior art and its limits, and anything shipped must follow one rule: **every output traces to a check that ran; anything inferred but not verified is labeled as such.**

## Row ownership: access to other people's data as a build error

Declare that a table's rows belong to a user (in a SQL comment such as `-- limen: owned_by owner_id`, or in `limen.toml`, so `schema.sql` stays plain SQL). Every query on that table must then filter on the owner column with a value that **provably comes from the signed-in identity** (`auth.sub`), or sit under `@allow_insecure("reason")`.

- **The hard part:** proving where the bound value comes from. `owner_id = $1` is meaningless if `$1` is a request parameter. This needs a must-flow analysis (identity provenance through helpers and modules), the mirror image of the existing taint summaries.
- **Also:** `limen schema --rls` generates PostgreSQL row-level security policies from the same declaration, so a query the analysis can't see is still enforced by the database.
- **Prior art:** Ur/Web's UrFlow (OSDI 2010) checks row-level policies statically. Qapla, Hails, Sesame, and Scooter & Sidecar (PLDI 2021) are related. Supabase and Hasura enforce declared row permissions at run time. What's new here is bringing it to a practical, agent-friendly language with one visible waiver.
- **Limits to start with:** joins, CTEs and upserts handled conservatively, and documented.

## Access rules in plain English

`limen policy` prints what each route actually allows, for example: `DELETE /users/{id}: any signed-in user can delete any user`. It is the rendering layer of row ownership.

- Guards are arbitrary code, so only a small set of idioms is summarized (signed in, role equality, ownership lookup). Anything else is printed as `custom check at auth.lmn:12, not summarized`. No guessing, no AI.
- Also served through `limen mcp`, so an agent reads the access model before editing.

## Security diff and ratchet

`limen diff main..branch` shows changes in what the program statically can do: new hosts, new sinks reached, guards removed, new `@public` routes. `limen diff --check` fails CI when that surface grows without a waiver.

- **Prior art:** GitHub code scanning on pull requests, Semgrep diff-aware scans, oasdiff and buf for API breaks. The capability diff is the new part.
- **Limit:** "statically visible capabilities", not everything the program can do (third-party crates and values from configuration aren't fully visible).

## Expiring waivers

`@allow_insecure("reason", until="2027-03-01")`: the build fails after the date, and `limen waivers` lists every waiver with its age. Security debt with an expiry date.

## Candidate exploits and `limen test --attack`

A refusal can suggest a request that would exploit the flaw, labeled `candidate, unverified`. `limen test --attack` runs candidates against the service, and only then calls one "working". Shares its machinery with the benchmark's probes and `limen fuzz`.

- **Canary secrets:** test mode fills every `Secret` with a known canary value and checks that it never appears in a log, response or error.
- **Prior art:** proof-based scanning in DAST tools (Invicti).

## Attested security report

Each release gets a report of what the compiler checked (every route has a policy, which sinks are covered, the schema hash for SQL checks, waivers with reasons), published as an in-toto attestation next to the existing provenance, SBOM and SARIF.

- Detached, not embedded in the binary: an embedded signature would break byte-for-byte reproducible builds.
- Framed as evidence an auditor can use, not as compliance itself.

## Sandbox profile

Generate a best-effort sandbox from the capabilities the compiler can see: a Landlock and seccomp profile, a systemd unit, or Dockerfile settings, plus a learning mode that records what the service actually does in staging.

- **Limits, stated up front:** Linux only. Landlock restricts files and TCP ports, not hostnames; restricting hosts needs an egress proxy. Paths and hosts read from configuration aren't known at compile time. It is a floor, not a ceiling, and never "the binary can't do more than its source shows".

## Benchmark

Before building row ownership, measure how often agents introduce access-control bugs in change requests to an existing service, in Limen and in Rust, and keep that baseline. Re-run after the feature exists and publish the difference. See [bench/](bench/).
