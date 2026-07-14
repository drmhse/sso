# GitHub security administration checklist

The repository workflows provide dependency review, npm and Rust advisory
checks, and JavaScript/TypeScript CodeQL analysis. The following protections
cannot be enabled by a committed file and require a repository administrator:

- Enable the dependency graph, Dependabot alerts, and Dependabot security
  updates under **Settings > Advanced Security**.
- Enable GitHub secret scanning and push protection. Public repositories receive
  GitHub's public secret scanning coverage automatically, but repository push
  protection and private-repository coverage depend on repository settings and
  plan eligibility.
- Enable private vulnerability reporting so researchers can report issues
  without first disclosing them publicly.
- Require the `Dependency changes`, `npm dependency audit`, `Rust
  dependency audit`, and `CodeQL (JavaScript and TypeScript)` checks in the
  default-branch ruleset after each check has completed successfully once.
- Restrict workflow permissions to read-only by default and keep approval
  required for workflows submitted from first-time or fork contributors.

CodeQL does not support Rust. Rust coverage in this repository therefore uses
`cargo-audit` for dependency advisories and the separate CI workflow for
compiler and Clippy findings; neither is a substitute for a Rust-focused manual
security review.

No repository or third-party credential is passed to the security workflow.
Secret scanning is intentionally delegated to GitHub's native facility instead
of placing a token-bearing third-party scanner in pull-request automation.
