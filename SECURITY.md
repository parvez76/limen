# Security policy

Parvez generates every line of the services it builds, so a flaw in Parvez becomes a flaw in each of them. Security reports get priority over feature work.

## Reporting a vulnerability

**Don't open a public issue.** Report privately through GitHub: open the repository's **Security** tab, choose **Report a vulnerability**, and describe:

- the Parvez version (`parvez --version`) and target platform;
- a minimal `.prvz` / `.msd` program, or the request sequence, that shows the problem;
- what an attacker gains: for example, reading another user's data, running code, or bypassing a guard;
- whether it's already public or being exploited.

What to expect:

| Step | Target |
|---|---|
| Acknowledgement | 3 business days |
| Assessment and severity (CVSS 3.1) | 10 business days |
| Fix for critical and high severity | 30 days from confirmation |
| Advisory | published as a GitHub Security Advisory with a CVE once a fix is released; the reporter is credited unless they ask not to be |

Please give us a chance to ship the fix before disclosing. If a deadline matters to you, say so in the report.

## Supported versions

Parvez is pre-1.0: only the latest minor release receives security fixes. Upgrade by installing the new release (see [Verifying a release](#verifying-a-release)) or with `git pull && cargo install --path . --locked`, then rebuild your services, because fixes to generated code and runtime only reach a service when it's rebuilt.

| Version | Security fixes |
|---|---|
| 0.16.x | yes |
| < 0.16 | no |

## Verifying a release

Every release from v0.16.0 on is built by [`.github/workflows/release.yml`](.github/workflows/release.yml) when a `v*` tag is pushed. The tests must pass first. Each archive then gets a GitHub build attestation: a keyless Sigstore signature tying the file to the exact commit and workflow run that produced it. The release also lists `SHA256SUMS`.

```bash
# 1. checksum
sha256sum -c SHA256SUMS --ignore-missing
# 2. provenance: built from this repository by the release workflow
gh attestation verify parvez-v0.16.0-x86_64-unknown-linux-musl.tar.gz --repo parvez76/project-parvez
```

Builds are reproducible: the workflow rebuilds the Linux binary from scratch in a different directory and refuses to publish if a single byte differs. You can check a release yourself with the same Rust version:

```bash
git clone https://github.com/parvez76/project-parvez && cd project-parvez && git checkout v0.16.0
.github/release-build.sh x86_64-unknown-linux-musl /tmp/rebuild   # prints the archive's SHA-256
grep x86_64-unknown-linux-musl SHA256SUMS                         # must match
```

Release tags from v0.16.0 on are signed with the project's SSH signing key, listed in [`.github/allowed_signers`](.github/allowed_signers) (fingerprint `SHA256:FRGXW2DjW+ITeT31kbI1ZZTrpXsglQBuWgcIS4/q4JA`). GitHub shows them as Verified; to check locally:

```bash
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers tag -v v0.16.0
```

Installing from source (`cargo install --git https://github.com/parvez76/project-parvez --tag v0.16.0 --locked`) uses the exact dependency versions in `Cargo.lock`.

## Scope

In scope:

- the compiler (`parvez`), including its parser, which reads untrusted source;
- generated code and the runtime it embeds: HTTP handling, OIDC tokens and browser sessions, CSRF checks, Masud HTML escaping, `Secret`, `safe_join`, error handling, limits, WebSockets;
- the security lint giving a false negative for a pattern its rules claim to catch;
- the MCP server (`parvez mcp`);
- `parvez build` supply-chain checks (RustSec audit, SBOM).

Out of scope:

- code inside an item marked `@allow_insecure("reason")`, which deliberately opts out;
- vulnerabilities in a dependency crate that Parvez's audit already reports; report those to RustSec or the crate;
- logic flaws in your own program, such as a guard function that returns the wrong answer;
- denial of service that needs more traffic than the configured limits allow.

## What Parvez enforces

These protections are on by default. Where a check is a compile error, the program doesn't build until it is fixed or explicitly waived. References: [CWE](https://cwe.mitre.org), [OWASP Top 10 2021](https://owasp.org/Top10/), [OWASP ASVS 4.0.3](https://owasp.org/www-project-application-security-verification-standard/).

| Protection | How | CWE | OWASP | ASVS |
|---|---|---|---|---|
| Deny-by-default access | every route, socket and page needs `@guard(fn)` or `@public("reason")`, else compile error; `parvez routes` prints the access map | 862, 284 | A01 | 1.4.1, 4.1.3, 4.1.5 |
| SQL injection | lint rule `sql-injection` | 89 | A03 | 5.3.4, 5.3.5 |
| OS command injection | lint rule `command-injection` | 78, 77 | A03 | 5.3.8 |
| Path traversal | lint rule `path-traversal`; `safe_join` | 22 | A01 | 12.3.1, 12.3.2 |
| Cross-site scripting | Masud HTML-escapes every interpolated value in text and attributes; unescaped output needs an explicit `raw` line | 79 | A03 | 5.3.3 |
| Hard-coded credentials | lint rule `hardcoded-secret` | 798, 259 | A07 | 2.10.4, 6.4.1 |
| Secrets in logs or responses | `Secret` prints `[redacted]`, has no serializer, can't be returned from a route; lint rules `secret-exposure` and `secret-type` | 532, 200, 312, 316 | A09, A04 | 7.1.1, 7.1.2, 8.3.6 |
| Timing attacks on secrets | `Secret` comparison hashes both sides (SHA-256) and compares the digests with the audited `subtle` crate: no early exit, and the secret's length isn't revealed | 208 | A02 | - |
| Token validation | OIDC: asymmetric algorithms only, issuer, audience, expiry and token type checked; fails closed when unconfigured | 347, 287 | A07 | 3.5.3 |
| Session security | AES-256-GCM encrypted cookies, `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax`, PKCE, back-channel logout and periodic IdP re-check | 384, 613, 614, 1004 | A07 | 3.4.1, 3.4.2, 3.4.3, 3.4.4 |
| Cross-site request forgery | state-changing session requests must come from the same origin | 352 | A01 | 4.2.2 |
| Error details | internal errors and panics become a generic 500; details stay in server logs | 209 | A04 | 7.4.1 |
| Resource exhaustion | body size limit, request timeout, concurrency backpressure | 400, 770 | A04 | - |
| Script injection in pages | `Content-Security-Policy` on HTML: scripts only from the service's own origin (no inline scripts, event-handler attributes or `eval`), no plugins, no framing, no `<base>` hijack, forms post only to the service (and the identity provider, for sign-out). Other responses get `default-src 'none'` | 79, 1021 | A03, A05 | 14.4.3 |
| Downgrade to HTTP | `Strict-Transport-Security: max-age=31536000` (browsers ignore it over plain HTTP, so local development is unaffected) | 319 | A02 | 14.4.5 |
| Clickjacking and sniffing | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` | 1021, 693 | A05 | 14.4.4, 14.4.6, 14.4.7, 8.2.1 |
| Vulnerable dependencies | build fails on RustSec advisories (`[security] audit = "deny"`); CycloneDX SBOM per build | 1395 | A06 | 14.2.1, 14.2.5 |
| Memory safety | Parvez code compiles to Rust without `unsafe` blocks (the language has no `unsafe`) | 119, 787, 416 | - | - |

### What `Secret` does and doesn't guarantee

`Secret` keeps a value out of logs, output and JSON at compile time; that part is enforced. Its memory and timing protections are best effort, as they are in Java, .NET and every other language:

- **Zeroing:** the `Secret`'s own memory is overwritten on drop with the `zeroize` crate, which uses volatile writes the compiler can't remove. Copies made from `s.expose()`, and older buffers a `String` left behind when it grew, aren't wiped. Swap, core dumps and hibernation files are outside a program's control.
- **Constant time:** comparison hashes both sides and compares the digests with `subtle`, which adds optimization barriers. No language can guarantee that a future compiler or CPU won't introduce timing differences.

## Rules

The compile-time lint rules, as shown by `parvez lint --rules` and in every finding's `= see:` line:

| Rule | Catches | CWE | OWASP 2021 | ASVS 4.0.3 | Severity |
|---|---|---|---|---|---|
| `sql-injection` | SQL built from interpolation or `+` | 89 | A03 Injection | 5.3.4, 5.3.5 | 9.8 |
| `command-injection` | dynamic program name, or dynamic `sh -c` script | 78, 77 | A03 Injection | 5.3.8 | 9.8 |
| `path-traversal` | request input reaching the filesystem without `safe_join` | 22 | A01 Broken Access Control | 12.3.1, 12.3.2 | 7.5 |
| `hardcoded-secret` | literals in secret-named bindings, key-shaped literals, `secret("...")` | 798, 259 | A07 Identification and Authentication Failures | 2.10.4, 6.4.1 | 7.5 |
| `secret-exposure` | `.expose()` reaching logs, output, errors, JSON or pages | 532, 200 | A09 Security Logging and Monitoring Failures | 7.1.1, 7.1.2 | 6.5 |
| `secret-type` | a secret-named `state:` field typed `str` | 312, 316 | A04 Insecure Design | 8.3.6, 6.4.1 | 4.0 |

Untrusted input comes from text-carrying route parameters (numbers, `bool` and `char` can't hold a path or script), `body`, `query`, `req`, a socket's `conn` and the inputs of guard functions. It is followed through derived values and into the functions and methods it's passed to, across modules, helper chains and recursion (per-parameter summaries computed to a fixed point). Method calls are resolved by the receiver's type, inferred from struct literals, annotations, parameter and `state:` field types, list elements (`[Disk(..)]`, `Vec<Box<dyn Store>>`) and the declared return types of your functions; calls through a `dyn Trait`, `Arc<dyn Trait>` or a generic bounded by a trait follow every implementation. Request data stored in a `state:` field taints every later read of it, in any route, worker or function, and the finding says where it was stored. A method that stores its argument in its object (`job.set_path(name)`) makes the object hold request data. Values read from the database (`fetch_one`, `fetch_all`, `query_as`, ...) are untrusted for file paths and commands, because an earlier request may have written them (second-order injection); a value declared as a number, `bool` or `char` is never treated as text. Known limits: data handed between tasks through a channel whose sending and receiving ends are different `state:` fields isn't followed; contents of files, environment variables and outgoing HTTP responses aren't treated as untrusted; and a method call on a value whose type can't be inferred is followed only when exactly one `impl` defines that name.

The checks are tested against an adversarial corpus ([tests/security_corpus](tests/security_corpus)): programs that try to sneak request data, SQL and secrets past the rules through aliases, transforms, branches, loops, closures, helper chains, modules, methods and recursion, plus safe programs that must not be flagged. Every expected finding must be reported and nothing else may be; the known blind spots above are annotated there and fail the test once they start being caught, so the list stays accurate. Found a bypass or a false positive? A new corpus case is the best report.

## Code scanning (SARIF)

`parvez lint --sarif` writes SARIF 2.1.0, which GitHub code scanning, Azure DevOps, GitLab and DefectDojo import. Each rule carries its CWE tags and a severity score. Findings waived with `@allow_insecure("reason")` are included as suppressed results with that reason, so reviewers can see what was waived and why. File paths are relative to the repository root.

```yaml
# .github/workflows/parvez-security.yml
name: parvez security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --git https://github.com/parvez76/project-parvez --tag v0.16.0 --locked
      - run: parvez lint main.prvz --sarif -o parvez.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: parvez.sarif
```

`parvez lint` exits 1 when there are unwaived findings, so the job fails; `if: always()` still uploads the report.
