# How Limen was built

Limen was built by me, a DevOps engineer. I set the goals and decided the priorities and the trade-offs. [Claude Code](https://claude.com/claude-code) wrote most of the code, tests and documentation, under my direction and review. Commits are in my name because I'm responsible for them.

**Why say so.** It's the point of the project. Limen exists because AI agents now write a lot of backend code, and they forget things like permission checks. A language an agent can't write those mistakes in is most convincing when it was itself built that way and held up.

**What keeps it honest.** Speed is only worth something if the result is checked:

- 139 tests (104 unit, 35 integration that compile and run real programs), on Linux and Windows, on every change.
- An adversarial security corpus: code written to sneak request data, SQL and secrets past the checks, including documented blind spots that fail the build if they change. Every release must pass it; so must the [playground](https://parvez76.github.io/limen/play/).
- Outside review. I gave the repository to other AI models to critique, with no instructions to be kind. They found real bugs. The worst was a security analysis that silently stopped following a call chain after 32 functions, now fixed and tested at 100. They also found claims stronger than the evidence, which were corrected.
- Releases are signed, reproducible byte for byte, and attested by GitHub.

**What this doesn't mean.** Nobody outside the project has audited Limen. It has one maintainer and is pre-1.0. Being built quickly doesn't make it wrong, but it doesn't make it proven either: it has to earn trust the slow way, with use, bug reports and time. If you find a way past a check, [that's the most useful thing you can send](../CONTRIBUTING.md).
