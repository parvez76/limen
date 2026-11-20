# Changelog

Parvez is pre-1.0: a minor version can change syntax or defaults. Entries marked **Breaking** say what to change. Release tags from v0.16.0 on are signed; see [SECURITY.md](../SECURITY.md#verifying-a-release).

## v0.18.0
- Windows support (beta): `irm https://parvez76.github.io/parvez/install.ps1 | iex` installs a verified x64 build to `%USERPROFILE%\.parvez\bin` and adds it to the user PATH without admin rights. Releases include `x86_64-pc-windows-msvc`. CI builds and tests the compiler, the installer, `doctor`, `new`, `test` and `upgrade` on Windows.
- `parvez doctor` checks for the Visual Studio C++ build tools on Windows; `parvez upgrade` replaces the running `parvez.exe` safely.
- `parvez fmt` keeps a file's CRLF line endings.
- Error messages show module paths with `/` on every platform.
- Security fix: the analysis now runs to a fixed point with no depth limit. Before, a call chain deeper than about 32 functions, or request data copied through more than 32 `state:` fields, could reach a sink unreported. If the analysis's safety limit is ever hit, the build fails instead of passing. The corpus now includes a 100-function chain and a 50-field state chain.

## v0.17.1
- The repository is now `parvez76/parvez`. The installer moved to `https://parvez76.github.io/parvez/install.sh`; the old address no longer works.
- `parvez upgrade` and the installer point at the new name, and accept build attestations made under the old one (v0.16.0, v0.17.0).

## v0.17.0
- One-line installer: `curl -fsSL https://parvez76.github.io/parvez/install.sh | sh`. It verifies the download against `SHA256SUMS` (and the build attestation when `gh` is installed), installs to `~/.parvez/bin`, updates PATH, offers to install Rust, and says how to install a missing C linker.
- `parvez upgrade [--version] [--check] [--force]`: verified self-update.
- `parvez doctor`: checks Rust 1.88+, cargo, the C linker, git, the advisory database, targets and PATH, each with its fix. A build that fails for lack of a linker now points here.
- Landing page and installer on GitHub Pages.

## v0.16.0
- Signed, reproducible release binaries for Linux (x86_64, ARM64; static) and macOS (Apple silicon): GitHub build attestations, `SHA256SUMS`, and a byte-for-byte rebuild check before publishing. Release tags are signed.
- Security checks: objects that store request data through methods, method calls on values typed by inference (lists, return types), and second-order flows from database reads into file paths and commands.

## v0.15.0
- Security checks follow request data through trait objects and generics (every implementation of a `dyn Trait` call) and through `state:` (stored by one request, used by another route or worker).

## v0.14.0
- **Breaking:** a strict `Content-Security-Policy` on every page and `Strict-Transport-Security` on every response, configurable with `PARVEZ_CSP` / `PARVEZ_HSTS`. Pages with inline `<script>` or `onclick=` must move the script to a file.

## v0.13.1
- `Secret` compares SHA-256 digests with the audited `subtle` crate; SECURITY.md documents exactly what `Secret` guarantees.
- Numeric path parameters are no longer flagged.
- An adversarial security corpus that every release must pass.

## v0.13.0
- Security checks follow request data into helper functions, methods and other modules. `req`, WebSocket messages and guard inputs count as untrusted.

## v0.12.0
- Every security rule maps to CWE, OWASP Top 10 and ASVS. `parvez lint` with SARIF 2.1.0 output for code scanning. Security policy (SECURITY.md).

## v0.11.0
- `Secret`: zeroized on drop, compared in constant time, prints as `[redacted]`, never serialized or returned as JSON, with rules for exposure, plain-`str` secrets and hard-coded values.
- Type names that would shadow Rust built-ins or the runtime (`Result`, `Option`, `AppError`, ...) are rejected with a clear error.

## v0.10.0
- **Breaking:** deny-by-default access control. Every route, socket and page needs `@guard(...)` or `@public("reason")`. Add `@public` to endpoints that are deliberately open.
- `parvez routes` prints the access map.

## v0.9.3
- Instant session revocation: OIDC back-channel logout plus a periodic re-check with the identity provider.
- Masud: inline SVG, `canvas`, `data-*` attributes and format specs. Sign out works for form posts.

## v0.9.2
- `@guard` on Masud pages.

## v0.9.1
- Generics and traits (`async` and `dyn`), map literals and `json({...})`, `catch`, `as`, `priv`, `parallel`, `every` workers, `@test_only` code, guard access to path params.
- Browser sign-in for Masud pages: OIDC code flow with PKCE and encrypted session cookies.
- `parvez fmt`, `parvez new`, cross-compilation and `.sha256` checksums.

## v0.9
- `test` blocks and `parvez test`, observability (JSON logs, Prometheus metrics, health checks), OIDC bearer tokens.

## v0.8
- `const`, `if` expressions, `if let`, embedded frontends, TypeScript types (`parvez types --ts`), and Masud, the HTML template language.

## v0.7
- Multi-file modules, WebSockets, ergonomics, compiler hardening.

## v0.6
- Request access, route guards, status codes, closures, `spawn`, and a supply-chain check of only the crates actually compiled.

## v0.5
- Hardened services, the compile-time security checks, the RustSec gate, SBOMs and `parvez fuzz`.

## v0.4
- Shared state, uniform JSON errors, keyword escaping, the MCP server.

## v0.3
- Crate imports, async/await, `@json`, HTTP routes, `parvez check`.

## v0.2
- Source-line mapping of errors, enums, `match`, `impl` blocks.

## v0.1
- Lexer, parser, Rust code generation, and the `build` / `run` / `show` commands.
