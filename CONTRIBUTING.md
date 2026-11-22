# Contributing to Parvez

Thanks for looking. The most valuable contribution is the simplest one:

## 1. Break a security check (the best report there is)

Find a way to get request data into a file path or shell command, SQL built from strings, or a `Secret` into a log, without Parvez stopping it. Then:

1. Reproduce it in the [playground](https://parvez76.github.io/parvez/play/) and press **Share** for a link, or write it as a small `.prvz` file.
2. Open a [check bypass issue](https://github.com/parvez76/parvez/issues/new?template=check-bypass.yml), or a pull request that adds the case to [`tests/security_corpus/`](tests/security_corpus/) with a `# expect: rule` comment on the line that should be caught.

Every release must pass the corpus, so your case becomes a permanent guarantee. Bypasses are credited in the [changelog](docs/CHANGELOG.md).

A false alarm (safe code that Parvez refuses) is just as useful: [report it](https://github.com/parvez76/parvez/issues/new?template=false-alarm.yml), or add it to `tests/security_corpus/safe.prvz`.

**A vulnerability in Parvez itself** (the compiler, the generated services, the installers, the release process) is different from a missed check: report it privately as described in [SECURITY.md](SECURITY.md).

## 2. Build and test

You need Rust (via [rustup](https://rustup.rs)) and a C linker.

```bash
git clone https://github.com/parvez76/parvez && cd parvez
cargo test --release        # unit tests, then integration tests that compile real programs (a few minutes)
cargo run --release -- lint tests/security_corpus/flows.prvz
```

The playground builds from the same sources:

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown --manifest-path playground/Cargo.toml
node playground/test.mjs    # must report exactly what the CLI reports on the corpus
```

Where things are: `src/lexer.rs` → `src/parser.rs` → `src/security.rs` (the checks) → `src/codegen.rs` (Rust generation); `src/main.rs` is the CLI. [docs/REFERENCE.md](docs/REFERENCE.md#working-on-parvez-itself) has the full layout.

## 3. Pull requests

- One topic per pull request, with a test that fails without it. CI runs everything on Linux and Windows.
- Security-check changes need corpus cases, both the thing now caught and the safe code that must stay allowed.
- A language change (new syntax or behavior) needs SPEC.md updated in the same pull request: SPEC.md is what AI agents read, so it must match the compiler exactly. Please open an issue first to discuss it.
- Keep the honest tone of the docs: say what something does and doesn't do.

## Conduct

Be kind and assume good faith. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
