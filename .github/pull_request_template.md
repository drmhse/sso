## Problem and solution

Describe the problem, the chosen solution, and why this scope is appropriate.

## Security and compatibility

- Authentication, authorization, tenant-isolation, or secret-handling impact:
- API, SDK, configuration, migration, or rollback impact:
- Documentation and public-claim impact:

## Verification

List the exact checks run and their results. Include allowed and denied cases
for authentication or tenant-boundary changes, and screenshots for visible UI
changes.

- [ ] Rust formatting, strict Clippy, and affected tests pass.
- [ ] JavaScript lint, typechecking, affected tests, and builds pass.
- [ ] Database migrations and affected backend features were exercised.
- [ ] User/operator documentation and changelog were updated where required.
- [ ] This change contains no credentials, tokens, private data, or generated build output.
