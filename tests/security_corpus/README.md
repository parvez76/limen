# Security corpus

Adversarial programs for the security checks. `tests/cli.rs` (`security_corpus`) lints every top-level `.prvz` file here and compares the findings with the annotations:

- `# expect: rule` on a line: `parvez lint` must report that rule on that line.
- `# known-miss: rule`: a documented blind spot (see SECURITY.md). It must *not* be reported yet; when the analysis learns to catch it, the test fails and the annotation becomes `expect`.
- Any other finding is a false positive and fails the test.

Add a case whenever a bypass or a false positive is found.
