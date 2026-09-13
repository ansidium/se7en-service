# SE7EN Service

Source code for the Windows maintenance service used by 7Launcher, published
by SE7EN Solutions for inspection by users and security researchers.

The service performs authorized file and registry maintenance that requires
administrator privileges. It lets the launcher run normal tasks without
elevation. This repository contains the service, its command-line manager,
the service installer, and automated tests.

## What runs on Windows

| Component | Role |
| --- | --- |
| `Se7enService.exe` | Demand-start Windows service, registered as `SE7ENService` and displayed as `SE7EN Service`. Runs as `LocalSystem`. |
| `Se7enServiceManager.exe` | Client and lifecycle helper. Installation and removal require elevation. Its update helper can restart the validated launcher using the manager's own process token. |
| `se7en-service-setup.exe` | Installer for the shared service, with its own uninstall entry. |

The installed executable is `%ProgramFiles%\7Launcher\Service\Se7enService.exe`.
Protected state is stored under `%ProgramData%\SE7EN\Service`.

The service uses a local named pipe, `\\.\pipe\SE7ENService-v1`. Its typed
protocol supports registered installation roots, signed file sets, bounded
registry changes, and transaction status. The privileged service has no command
for executing arbitrary programs, shell commands, or scripts. Downloads,
network transports, the launcher UI, and ordinary game launches are outside
the service.

## Security design

- Windows pipe impersonation supplies the caller's identity. Root and registry
  scope registration require an elevated administrator token; jobs enforce
  their ownership and access rules.
- An embedded Ed25519 public key authenticates replaceable keyrings. Signed
  manifests bind product identifiers, generations, file sizes, and SHA-256
  digests. Rollback and conflicting-generation checks reject stale or
  inconsistent jobs.
- File operations are confined to registered roots, with checks for path
  traversal, reparse points, hard links, and changed filesystem identities.
  Registry operations use registered scopes and explicit value allowlists.
- Transactions journal their progress and support recovery. Service upgrades
  validate the local bundle, check health, and support rollback.
- Authenticode checks use local trust information without online revocation
  retrieval. They do not provide a live certificate-revocation check.

The implementation is in [`src/`](src/); the wire contract is in
[`src/protocol.rs`](src/protocol.rs). See [SECURITY.md](SECURITY.md) for reporting
and review entry points.

## Build and check

Use Windows 10 or later, Visual Studio Build Tools with the C++ toolchain and
Windows SDK, and [Rustup](https://rustup.rs/). Run these commands from this
repository's root. `rust-toolchain.toml` pins Rust and the Windows target;
`Cargo.lock` pins the resolved dependencies.

```powershell
cargo fmt --all -- --check
cargo clippy --locked --all-targets --target i686-pc-windows-msvc -- -D warnings
cargo test --locked --target i686-pc-windows-msvc
cargo build --release --locked --target i686-pc-windows-msvc
```

Cargo produces `target/i686-pc-windows-msvc/release/service.exe` and `client.exe`.
The distribution names are `Se7enService.exe` and `Se7enServiceManager.exe`.
These local outputs are unsigned. Tests use synthetic data and test keys;
production signing keys are not needed to build or run the default tests.
The explicitly ignored release-bundle test requires a separately supplied,
production-signed bundle and is not part of the default test run.

The Inno Setup source is in [`installer/`](installer/). Compile it with
`/DMaintenanceBundleDir=<verified-bundle-directory>` and the publisher's signing
configuration. An unsigned local build is not a production installation bundle.

## Source and releases

Download the existing signed distribution files from
[SE7EN Service 1.0.2 (gen 4)](https://github.com/ansidium/se7en-service/releases/tag/v1.0.2-generation.4).
The release includes the service, manager, signed bundle manifests, and
`SHA256SUMS.txt`. These files retain their original bytes and
signatures; they were not rebuilt or re-signed for this publication.

The source starts with a standalone snapshot and contains no launcher application
source or private repository history. Release notes identify the generation and
verification performed. For an antivirus report, use the exact affected file
and its SHA-256; the version string alone does not distinguish release generations.

Copyright (c) 2026 SE7EN Solutions. All rights reserved. The source is available
for review under [LICENSE.txt](LICENSE.txt); it is not distributed under an
open-source license. Dependencies retain their own licenses.
