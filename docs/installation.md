# Linux sandbox-service installation details

This document describes the deployment-specific Linux payload for the root
`openbox-sandbox` mTLS service. It does not describe the cross-platform `obs`
launcher artifacts, whose retained download names are
`openbox-sandbox-<platform>`; see
[`../packaging/launcher/README.md`](../packaging/launcher/README.md). The two
release tracks are not interchangeable, and OpenShell remains an external
runtime dependency in both.

The supported service installation command is always:

```sh
./install.sh
```

The installer starts as the current non-root user, determines the installation mode, performs non-root preparation, and requests administrator authorization only when protected system state must change.

## Automatic mode selection

### Verified service-release mode

If an adjacent `release/` directory exists, the installer treats it as a
published, deployment-specific sandbox-service payload. It performs no source
build and never substitutes newer artifacts. This layout is not the GitHub
launcher-asset directory.

The bundle layout is:

```text
install.sh
deploy/openbox-sandbox.service
release/
  SHA256SUMS
  openbox-sandbox
  service.json
  tls/client-ca.crt
  tls/server.crt
  tls/server.key
  runtime-mtls/ca.crt
  runtime-mtls/tls.crt
  runtime-mtls/tls.key
  openshell/source-commit
  openshell/*.deb
  # RPM bundles use both of these instead:
  # openshell/openshell-*.rpm
  # openshell/openshell-gateway-*.rpm
```

The OpenShell payload may be omitted only when the exact pinned build is already installed. `SHA256SUMS` must cover every other file in `release/`.

Before mutation, the installer rejects:

- missing or extra release files;
- links and special files;
- checksum mismatches;
- an unapproved OpenShell source revision;
- OpenShell binaries that do not identify the approved revision;
- unsafe ownership or modes; and
- invalid service configuration.

The approved OpenShell revision is:

```text
f169084923503a02a94425857b938de2841cab0c
```

### Local-development mode

If no adjacent `release/` directory exists, the installer enters a clearly labelled, non-production bootstrap. `--local` selects the same path explicitly.

This mode currently supports Debian-family Linux. It:

1. asks before installing missing build and runtime packages;
2. provisions rootless Podman;
3. installs checksum-pinned Rustup 1.28.2 when needed;
4. installs and selects Rust 1.95.0;
5. fetches OpenShell at the exact approved Git revision;
6. builds OpenBox and OpenShell from their locked dependency graphs;
7. packages the pinned OpenShell binaries locally;
8. generates a 30-day local CA, service identity, runtime identity, and administrator identity;
9. creates and checksums a local release payload; and
10. hands that payload to the same verified system installer used by release mode.

Generated material stays under the ignored, mode-`0700` directory:

```text
.openbox-local/
```

Caller credentials are written below:

```text
.openbox-local/clients/runtime/
.openbox-local/clients/admin/
```

These short-lived credentials and the local deployment are for development only. They are not an approved production release identity.

## Privileges and package installation

Do not invoke the installer with `sudo`. Run `./install.sh` as your normal user.

The installer performs initial checks without privilege and explains required mutations before invoking `sudo`. The privileged phase sanitizes its environment and independently repeats release validation before changing the system.

Administrator access is used only for operations such as:

- installing explicitly approved missing packages;
- creating the locked service account;
- writing protected configuration, identity, and state paths; and
- installing and controlling systemd services.

Package-manager use requires interactive approval unless `--install-dependencies` was supplied. `--no-install-dependencies` makes missing packages a hard failure.

## Options

```text
--local                     Force local-development mode
--install-dependencies      Install missing packages without prompting
--no-install-dependencies   Never install missing packages
--no-start                  Install and validate without starting the service
-h, --help                  Show command help
```

Automation may pass a canonical absolute release path after the options. Ordinary users should rely on the adjacent `release/` directory and run only `./install.sh`.

## Installation and rollback

The system phase:

- snapshots and rechecks the exact release payload;
- installs files atomically with strict ownership and modes;
- validates the installed binary and configuration with `--check-config`;
- installs the hardened systemd unit;
- starts the pinned per-user OpenShell gateway;
- copies its generated mTLS client credentials into the OpenBox service boundary; and
- enables and starts OpenBox unless `--no-start` was supplied.

If OpenBox validation or startup fails, replaced OpenBox files are rolled back. Host packages and a separately installed OpenShell package are not silently removed during that rollback.

The OpenBox service has no forced stop timeout because shutdown must wait for ownership-aware sandbox cleanup.

## After installation

A caller must still validate the configured release and deployment identity and complete its own authorization preflight before accepting work.
