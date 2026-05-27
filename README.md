# CERBERUS Windows Agent

Per-machine Windows agent package for endpoint onboarding, secure agent identity, service-mode polling, telemetry, diagnostics, and governed desktop operations.

## Quick Links

- Repository: https://github.com/BUZASLAN128/cerberus-windows-agent
- Releases: https://github.com/BUZASLAN128/cerberus-windows-agent/releases
- Latest Release: https://github.com/BUZASLAN128/cerberus-windows-agent/releases/latest
- Auto Publish Workflow: https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/auto-publish-exe.yml
- CI Workflow: https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/ci.yml
- Create Public Release: https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/auto-publish-exe.yml

Badges:

[![CI](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/ci.yml)
[![Auto Publish](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/auto-publish-exe.yml/badge.svg?branch=dev)](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/auto-publish-exe.yml)
[![Latest Release](https://img.shields.io/github/v/release/BUZASLAN128/cerberus-windows-agent)](https://github.com/BUZASLAN128/cerberus-windows-agent/releases/latest)

## 1) Purpose

This project provides a Windows endpoint agent that:
- onboards a machine/user via SSO (Casdoor PKCE),
- registers the device to CERBERUS backend with an RSA public key,
- stores agent secrets securely with Windows DPAPI,
- runs as a Windows Service for heartbeat, telemetry, and governed command handling,
- reports telemetry and command results back to backend with signed requests.

Primary use cases:
- device onboarding for tenant-aware access,
- safe operational visibility via heartbeat and status snapshots,
- governed update and diagnostics flow for public agent releases.

## 2) Runtime Modes

The customer-facing runtime is split into purpose-specific executables:

- `Cerberus.Agent.Setup.exe`: EULA-backed setup UI, PKCE sign-in, device registration, portal claim wait, and service provisioning.
- `Cerberus.Agent.Tray.exe`: lightweight user-session tray status and repair entry point.
- `Cerberus.Agent.Service.exe`: Windows service runtime for heartbeat, telemetry, command polling, and update coordination.
- `Cerberus.Agent.Updater.exe`: signed/checksum-verified MSI update applier.
- `Cerberus.Agent.Uninstall.exe`: customer-facing uninstall wrapper with best-effort portal deactivation.

Support/admin CLI flags remain available through the setup binary for diagnostics and controlled automation:
`--register`, `--heartbeat-once`, `--service`, `--install-service`, `--uninstall-service`, `--start-service`, `--stop-service`, `--export-tailscale-up`, `--self-test`, `--apply-staged-update`, and `--accept-eula`.

Notes:
- Token/file based register flow is intentionally disabled in `--register`; PKCE browser flow is the single onboarding path.
- `--service` runs as LocalSystem only when launched by the installed Windows Service.
- `--accept-eula` is a support/headless path only; the customer MSI path uses the EULA dialog.

## 3) High-Level Architecture

- `src/Cerberus.Agent.App`
  - setup UI, support CLI, service provisioning, onboarding orchestration, local UI config.
- `src/Cerberus.Agent.Runtime`
  - shared runtime files linked into service, tray, updater, and uninstall binaries.
- `src/Cerberus.Agent.Tray`
  - lightweight WinForms tray process.
- `src/Cerberus.Agent.Service`
  - Windows service entry point.
- `src/Cerberus.Agent.Updater`
  - MSI update applier.
- `src/Cerberus.Agent.Uninstall`
  - uninstall wrapper.
- `src/Cerberus.Agent.Core`
  - API client, heartbeat loop, command dispatcher, telemetry/update contracts, idempotency cache.
- `src/Cerberus.Agent.Security`
  - DPAPI secret store, RSA request signer, token refresh manager.
- `src/Cerberus.Agent.Integrations.Ad`
  - AD readiness and guarded module boundary. AD mutation executors are not implemented in this foundation build.
- `src/Cerberus.Agent.Integrations.Tailscale`
  - status probe and `tailscale.ensure_connected` handler (safe/verify-first behavior).
- `src/Cerberus.Agent.Observability`
  - log/token redaction (`Sanitizer`) and file logger.

## 4) Backend API Contract

Core endpoints currently used by the agent:

- `POST /api/v1/agents/register`
  - called by `AgentRegistrar` with OAuth token, generated RSA public key, fingerprint, and build metadata.
  - persists returned `agent_id`, `tenant_id`, `agent_refresh_token`, and server-owned telemetry config.

- `POST /api/v1/agents/token`
  - called by `AgentTokenManager` to refresh access token using refresh token.
  - supports refresh-token rotation (new refresh token may be returned and persisted).

- `POST /api/v1/agents/{agentId}/heartbeat`
  - called by `AgentApiClient.HeartbeatAsync`.
  - returns pending commands and next poll interval.

- `POST /api/v1/agents/{agentId}/commands/{commandId}/result`
  - called by `AgentApiClient.SubmitCommandResultAsync`.
  - sends command result (`status`, `exit_code`, `stdout`, `stderr`, `post_verify`).

- `POST /api/v1/agents/{agentId}/snapshot`
- `POST /api/v1/agents/{agentId}/events`
- `POST /api/v1/agents/{agentId}/probe-results`
- `POST /api/v1/agents/{agentId}/diagnostic-bundles`
  - signed telemetry and diagnostics endpoints. Payloads are allowlisted and redacted.

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

AD and Windows mutation commands are not enabled as real executors in this foundation build. Windows mutation command families must pass explicit approval/audit guardrails and still fail closed until a governed executor is implemented.

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

## 7) Public Release Requirements

Public agent releases must be produced through `.github/workflows/auto-publish-exe.yml` or `scripts/build-agent-public-release.ps1`.

Required release inputs:

- `WINDOWS_SIGNING_CERT_BASE64`: base64-encoded PFX code-signing certificate.
- `WINDOWS_SIGNING_CERT_PASSWORD`: PFX password.
- `AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM`: Cerberus-owned RSA private key used only to sign update manifests.
- `AGENT_RELEASE_ARTIFACT_BASE_URL`: Cerberus-owned release artifact URL prefix.
- Optional: `TimestampUrl`, defaults to `http://timestamp.digicert.com`.

Local release builds require PowerShell 7+ (`pwsh`) because update manifest signing uses modern .NET PEM APIs. GitHub Actions already runs the release workflow with `pwsh`.

Installer builds use WiX Toolset v7 with explicit OSMF EULA acceptance (`AcceptEula=wix7`). This is the installer toolchain license decision, separate from the Cerberus Agent EULA shown to customers during MSI install.

Release gate output includes:

- signed `.exe`
- signed `.msi` installer
- `.zip`
- `.sha256`
- `.sbom.json`
- `.provenance.json`
- `.release-gate.json`
- `.update-manifest.json`

Unsigned public releases are denied. Tenant-controlled backend, update URL, signing key, channel, or artifact source is not supported.

### Preview MSI Customer Flow

Preview customer installs use the MSI asset from the mutable `preview-latest` GitHub release:

1. Download `Cerberus.Agent.Setup-preview-<version>.msi`.
2. Accept the MSI EULA dialog.
3. Complete the per-machine install under `Program Files\Cerberus\Windows Agent`.
4. The installer opens `Cerberus.Agent.Setup.exe`.
5. The setup UI handles PKCE login, registration, portal claim/lock, UAC service install/start, heartbeat, and ready state.

The MSI never calls `--accept-eula`. That flag remains a support/admin/headless test path only. After the MSI EULA dialog is accepted, Windows Installer writes consent metadata under `HKLM\Software\Cerberus\WindowsAgent\LegalConsent`; the agent imports that record into canonical `legal-consent.json` with `acceptedVia = "msi_eula_dialog"` before setup proceeds. The MSI does not use PowerShell custom actions for consent.

### MSI Public Properties

Enterprise deployment may pass non-secret public MSI properties:

- `CERBERUS_BACKEND_URL`
- `CERBERUS_SSO_BASE_URL`
- `CERBERUS_SSO_CLIENT_ID`
- `CERBERUS_SSO_SCOPE` (default: `openid profile email groups`)
- `CERBERUS_CHANNEL` (default: release channel)
- `CERBERUS_LANGUAGE` (`auto`, `en-US`, or `tr-TR`)
- `CREATE_DESKTOP_SHORTCUT` (default: `0`)
- `START_TRAY_ON_LOGIN` (default: `1`)
- `CERBERUS_EULA_ACCEPTED=1` only for approved managed/headless deployments.

These values are stored under `HKLM\Software\Cerberus\WindowsAgent`. Do not put secrets in MSI properties.

## 8) Local Smoke

Use the clean-install smoke helper for local verification:

```powershell
.\scripts\clean-install-smoke.ps1 -RunEnrollment
```

The smoke is read-only until `-RunEnrollment`, `-InstallService`, or `-StartService` is explicitly provided. It does not run `tailscale up`, create Windows users, or mutate Headscale/Tailscale state.

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

### Publish Runtime Bundle

```powershell
dotnet publish src/Cerberus.Agent.App/Cerberus.Agent.App.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=false `
  -p:DebugSymbols=false `
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

- Runs manually with `workflow_dispatch`.
- Uses provided `release_version`, `channel`, and optional release notes.
- Publishes split self-contained runtime files with computed `Version`.
- Builds the WiX MSI installer:
  - package name: `Cerberus.Agent.Setup-<channel>-<version>.msi`
  - per-machine install under `Program Files\Cerberus\Windows Agent`
  - mandatory MSI EULA dialog
  - registry-based EULA consent metadata, imported by the agent
  - no PowerShell custom action
  - desktop shortcut disabled by default
  - tray startup enabled by default
  - post-install launch: `Cerberus.Agent.Setup.exe`
- Produces full release package:
  - `*.exe`
  - `*.msi`
  - `*.zip`
  - `*.sha256`
  - `*.sbom.json`
  - `*.provenance.json`
  - `*.release-gate.json`
  - `*.update-manifest.json`
- Uploads package files as workflow artifacts.
- Creates a versioned GitHub release with package assets and notes.
- For `preview` channel, also refreshes the mutable `preview-latest` release pointer.

Manual preview dispatch:

```powershell
gh workflow run auto-publish-exe.yml `
  --ref dev `
  -f release_version=0.2.0-preview.1 `
  -f channel=preview `
  -f release_notes="Preview MSI installer with one-click setup UI"
```

Follow-up:

```powershell
gh run list --workflow auto-publish-exe.yml --limit 5
gh run watch <run-id>
gh release view preview-latest --web
```

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
