#!/bin/sh
# The project's quality gate: lints (warnings are errors) and dependency policy.
set -e
cargo clippy --all-targets -q -- -D warnings
cargo deny -L error check advisories bans licenses
