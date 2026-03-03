# CERBERUS Windows Agent

Single Windows executable for endpoint onboarding, secure agent identity, service-mode polling, and remote command execution.

## Quick Links

- Repository: https://github.com/BUZASLAN128/cerberus-windows-agent
- Releases: https://github.com/BUZASLAN128/cerberus-windows-agent/releases
- Latest Release: https://github.com/BUZASLAN128/cerberus-windows-agent/releases/latest
- Auto Publish Workflow: https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/auto-publish-exe.yml
- CI Workflow: https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/ci.yml
- Create Main Manual Release: https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/auto-publish-exe.yml

Badges:

[![CI](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/ci.yml)
[![Auto Publish](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/auto-publish-exe.yml/badge.svg?branch=dev)](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/auto-publish-exe.yml)
[![Latest Release](https://img.shields.io/github/v/release/BUZASLAN128/cerberus-windows-agent)](https://github.com/BUZASLAN128/cerberus-windows-agent/releases/latest)

## 1) Purpose

This project provides a Windows endpoint agent that:
- onboards a machine/user via SSO (Casdoor PKCE),
- registers the device to CERBERUS backend with an RSA public key,
- stores agent secrets securely with Windows DPAPI,
- runs as a Windows Service for continuous heartbeat + command execution,
- reports command results back to backend with signed requests.

Primary use cases:
- device onboarding for tenant-aware access,
- secure remote execution bridge (AD/Tailscale operations),
- operational visibility via heartbeat and status snapshots.

## 2) Runtime Modes

CLI flags are handled in `Program.cs` and `Args.cs`.

- `--tray` (default if no mode is given): WPF tray app for onboarding + status.
- `--register`: non-GUI registration flow (still opens browser for PKCE).
- `--service`: polling worker loop (service/runtime mode).
- `--install-service`: installs Windows service (`CerberusAgent`) and starts it.
- `--uninstall-service`: removes installed service.
- `--start-service`: starts service.
- `--stop-service`: stops service.
- `--export-tailscale-up`: exports `tailscale up` command file from stored preauth data.
- `--self-test`: runs offline and online smoke checks.
- `--self-test-json` / `--json`: JSON output for self-test.
- `--self-test-out <path>`: write self-test JSON report to file.

Notes:
- Token/file based register flow is intentionally disabled in `--register`; PKCE browser flow is the single onboarding path.
- `--service` runs as LocalSystem when launched via Windows Service.

## 3) High-Level Architecture

- `src/Cerberus.Agent.App`
  - mode selection, tray UX, service install/start/stop, onboarding orchestration.
- `src/Cerberus.Agent.Core`
  - API client, heartbeat loop, command dispatcher, contracts/models, idempotency cache.
- `src/Cerberus.Agent.Security`
  - DPAPI secret store, RSA request signer, token refresh manager.
- `src/Cerberus.Agent.Integrations.Ad`
  - AD command handlers (`ad.user.create`, `ad.user.update`, `ad.user.disable`).
- `src/Cerberus.Agent.Integrations.Tailscale`
  - status probe and `tailscale.ensure_connected` handler (safe/verify-first behavior).
- `src/Cerberus.Agent.Observability`
  - log/token redaction (`Sanitizer`) and file logger.

## 4) Backend API Contract

Core endpoints currently used by the agent:

- `POST /api/v1/agents/register`
  - called by `AgentRegistrar` with OAuth token + generated RSA public key + fingerprint + agent version.
  - persists returned `agent_id`, `tenant_id`, `agent_refresh_token`, optional Tailscale preauth data.

- `POST /api/v1/agents/token`
  - called by `AgentTokenManager` to refresh access token using refresh token.
  - supports refresh-token rotation (new refresh token may be returned and persisted).

- `POST /api/v1/agents/{agentId}/heartbeat`
  - called by `AgentApiClient.HeartbeatAsync`.
  - returns pending commands and next poll interval.

- `POST /api/v1/agents/{agentId}/commands/{commandId}/result`
  - called by `AgentApiClient.SubmitCommandResultAsync`.
  - sends command result (`status`, `exit_code`, `stdout`, `stderr`, `post_verify`).

- `POST /api/v1/agents/{agentId}/tailscale/preauth`
  - called by `AgentApiClient.GetTailscalePreauthAsync`.
  - returns `tailscale_login_server` + `tailscale_authkey`.

- `GET /health`
  - used by `SelfTestMode` online health probe.

### Signed Request Headers

`AgentApiClient` signs request body and sends:
- `Authorization: Bearer <access_token>`
- `X-Agent-Id`
- `X-Nonce`
- `X-Timestamp`
- `X-Body-Hash` (SHA-256 Base64)
- `X-Signature` (RSA SHA256 PKCS#1 v1.5 over canonical string)

Canonical format:

```text
v1:{METHOD}:{PATH}:{NONCE}:{TIMESTAMP}:{BODY_HASH}
```

## 5) Supported Command Types

Dispatched by `CommandDispatcher` and idempotency-protected.

- `agent.health.snapshot`
  - returns basic host info/uptime.

- `tailscale.ensure_connected`
  - verify-first mode.
  - does not automatically run `tailscale up` in this implementation.
  - writes `tailscale-up.cmd` when preauth data exists.

- `ad.user.create`
- `ad.user.update`
- `ad.user.disable`

Unknown command types are returned as `FAILED` with reason text and cached via idempotency key.

## 6) Security Model

### Secret Storage

Secrets are encrypted with Windows DPAPI:
- User scope: `%LOCALAPPDATA%\CerberusAgent\secrets.json`
- Machine scope: `%ProgramData%\CerberusAgent\secrets.json`

Stored secret payload includes:
- `agent_id`, `tenant_id`
- `refresh_token`
- agent `private_key_pem`
- backend URL
- optional Tailscale preauth fields

ACL hardening is applied best-effort:
- SYSTEM + Administrators full control.
- current interactive user can be granted access where needed for tray flows.

### Token Handling

- Access token is in-memory only.
- Refresh token is persisted encrypted (DPAPI).
- Rotation-aware refresh logic updates stored refresh token if backend rotates it.
- Expiration guard renews token before expiry (~30s skew).

### Signing and Integrity

- Every agent API request body is hashed and signed.
- Nonce + timestamp headers support replay protections on backend side.

### Redaction and Logging

`Sanitizer` redacts:
- token/secret/password/private key patterns,
- JWT-like values,
- Headscale key formats.

Self-test output is sanitized before printing/writing.

### Tailscale Safety

- Generated `tailscale-up.cmd` explicitly marks auth key as sensitive.
- In service/machine scope flows, command file ACL is hardened.
- Verify-first behavior avoids automatic risky network changes in legacy/test mode.

## 7) Configuration

### Environment Variables

Backend/SSO configuration:
- `CERBERUS_BACKEND_URL`
- `CERBERUS_SSO_BASE_URL` (preferred)
- `CERBERUS_SSO_CLIENT_ID`
- `CERBERUS_SSO_CLIENT_SECRET` (env-only, not persisted)
- `CERBERUS_SSO_SCOPE`
- `CERBERUS_OAUTH_REDIRECT_PORT`

Legacy compatibility variables are also accepted:
- `CERBERUS_CASDOOR_ENDPOINT`
- `CERBERUS_CASDOOR_CLIENT_ID`
- `CERBERUS_CASDOOR_CLIENT_SECRET`
- `CERBERUS_CASDOOR_SCOPE`

### UI Config File (Non-Secret)

`%LOCALAPPDATA%\CerberusAgent\ui-config.json` stores non-secret defaults:
- backend URL,
- SSO endpoint/client ID/scope,
- redirect port.

Secrets are never persisted in this file.

## 8) Local Development

### Prerequisites

- Windows 10/11
- .NET SDK 8.x

### Restore / Build / Test

Preferred project-based commands:

```powershell
dotnet restore src/Cerberus.Agent.App/Cerberus.Agent.App.csproj
dotnet restore tests/Cerberus.Agent.Core.Tests/Cerberus.Agent.Core.Tests.csproj

dotnet build src/Cerberus.Agent.App/Cerberus.Agent.App.csproj -c Release
dotnet test tests/Cerberus.Agent.Core.Tests/Cerberus.Agent.Core.Tests.csproj -c Release
```

### Publish Single EXE

```powershell
dotnet publish src/Cerberus.Agent.App/Cerberus.Agent.App.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -o out/release
```

### Preflight Gate

```powershell
./scripts/preflight.ps1
```

Preflight runs build + test + publish + self-test (unless skipped via script flags).

## 9) CI/CD and Auto Release

### `ci.yml`

- Runs automatically for `dev` and `develop` on `push` and `pull_request`.
- For `main`, run manually with `workflow_dispatch`.
- Performs restore/build/test.
- Publishes self-contained `win-x64` output as workflow artifact.

### `auto-publish-exe.yml`

- Runs automatically on every `push` to `dev` and `develop`.
- For `main`, run manually with `workflow_dispatch`.
- Calculates release metadata and semantic version:
  - `dev/develop`: auto prerelease version `0.1.{run}-{branch}.{sha8}`
  - `main` manual: uses provided `release_version` input (e.g. `1.2.0`)
- Publishes self-contained EXE with computed `Version`.
- Produces full release package:
  - `*.exe`
  - `*.zip`
  - `*.sha256`
- Uploads package files as workflow artifacts.
- Creates/updates GitHub release with package assets and notes.

This means every update on `dev/develop` automatically gets a versioned prerelease package, while `main` is manual and version-controlled.

## 10) Branch Policy

- Default integration branch is `dev`.
- All new work and updates should go to `dev` (or PRs targeting `dev`).
- `main` is reserved for explicit manual promotion/merge.

## Repository Standards

The repository includes multi-contributor baseline governance files:

- `CODEOWNERS`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `SUPPORT.md`
- `CODE_OF_CONDUCT.md`
- PR template
- Issue templates (bug/feature/config)
- Dependabot configuration

## 11) Service Behavior

Service name:
- `CerberusAgent` (display name: `CERBERUS Windows Agent`)

Install behavior:
- requires Administrator rights,
- starts automatically,
- sets recovery policy (restart on failure).

Execution loop:
- heartbeat polling with jitter,
- command dispatch with idempotency cache (`%ProgramData%\CerberusAgent\idempotency.json`),
- degraded mode on transient failures with retry delay.

## 12) Troubleshooting

- Registration fails with config errors:
  - verify `CERBERUS_BACKEND_URL`, `CERBERUS_SSO_BASE_URL`, `CERBERUS_SSO_CLIENT_ID`.

- Service cannot read secrets:
  - ensure machine-scope onboarding/registration exists for service context.

- Tailscale command not exported:
  - backend may not have returned preauth data yet,
  - run self-test and inspect `online.agent.tailscale_*` steps.

- CI works but `.slnx` local command fails:
  - use `.csproj`-based restore/build/test commands above.
