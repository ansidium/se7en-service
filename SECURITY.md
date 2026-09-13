# Security

## Report a potential vulnerability

Use [GitHub private vulnerability reporting](https://github.com/ansidium/se7en-service/security/advisories/new)
or email **info@se7en.ws** with the subject `SE7EN Service security report`.
Please keep exploit details out of public issues while a report is being assessed.

Include the source commit or binary version and SHA-256, Windows version,
required privileges, reproduction steps, and the expected and observed result.
Remove personal data and credentials from any supporting logs.

We assess reports against the latest source on the default branch. If the
report concerns a distributed binary, include its hash so it can be matched
to the appropriate release.

## Review entry points

| Boundary | Implementation |
| --- | --- |
| Strict IPC parsing and request limits | `src/protocol.rs` |
| Caller identity, authorization, named pipe and Authenticode | `src/windows.rs` |
| Signed keyrings, file sets and registry sets | `src/trust.rs`, `src/file_set.rs`, `src/registry_set.rs` |
| Registered paths and registry scopes | `src/roots.rs`, `src/registry_scopes.rs` |
| Transactions and recovery | `src/transaction.rs` |
| Service installation, upgrade and removal | `src/service_upgrade.rs`, `src/windows_upgrade.rs`, `installer/SE7ENService.iss` |
| Manager commands and launcher restart | `src/bin/client.rs` |

Automated tests cover these contracts using temporary files and synthetic
identities. The test signing keys are fixtures, distinct from the production
trust anchor. Passing tests are evidence for the tested cases, not a security
certification or antivirus verdict.
