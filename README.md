# Cerberus Windows Agent

Windows agent and service that enroll a machine with a Cerberus backend, report telemetry, and run backend-issued commands.

[![CI](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/ci.yml)
[![Auto Publish](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/auto-publish-exe.yml/badge.svg?branch=dev)](https://github.com/BUZASLAN128/cerberus-windows-agent/actions/workflows/auto-publish-exe.yml)
[![Latest Release](https://img.shields.io/github/v/release/BUZASLAN128/cerberus-windows-agent)](https://github.com/BUZASLAN128/cerberus-windows-agent/releases/latest)

- Releases: https://github.com/BUZASLAN128/cerberus-windows-agent/releases
- Third-party notices: [docs/legal/THIRD-PARTY-NOTICES.md](docs/legal/THIRD-PARTY-NOTICES.md)
- Contributing, security and support: [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [SUPPORT.md](SUPPORT.md)

## Build profiles

The profile is fixed at build time (`-p:AgentBuildProfile=server`, or `-BuildProfile server` in the release script). A backend or config setting cannot switch it.

| | Desktop (default) | Server |
|---|---|---|
| Product / service | Cerberus Windows Agent, `CerberusAgent` | Cerberus Server Agent, `CerberusServerAgent` |
| Data directory | `%ProgramData%\CerberusAgent` | `%ProgramData%\CerberusServerAgent` |
| Enrollment | Browser sign-in (Casdoor PKCE) from the tray panel | Headless, with a one-time enrollment proof entered in the MSI |
| User interface | Tray client and control panel | None |
| Commands | See [Commands](#commands) | `ping`, `collect_facts`, `agent_state` only |
| Snapshot interval | Default 60 s (60 s–24 h) | Default 3600 s (300–3600 s) |
| Release asset suffix | none | `-server` |

## Components

Installed under `Program Files\Cerberus\Windows Agent` (server: `Program Files\Cerberus\Server Agent`):

- `app/Cerberus.Agent.exe`: tray client and control panel (desktop) and the support CLI.
- `app/Cerberus.Agent.Service.exe`: Windows service. Heartbeat, telemetry, command polling, update coordination.
- `app/Cerberus.Agent.Updater.exe`: applies a verified MSI update.
- `app/Cerberus.Agent.Uninstall.exe`: uninstall wrapper that also unregisters the device from the backend when it can.

Source projects:

| Project | Contents |
|---|---|
| `src/Cerberus.Agent.App` | Tray UI, CLI, service provisioning, enrollment, telemetry section collectors, updates |
| `src/Cerberus.Agent.Core` | API client, heartbeat loop, command dispatch and envelopes, telemetry contracts |
| `src/Cerberus.Agent.Security` | DPAPI secret store, request signing, token refresh |
| `src/Cerberus.Agent.Integrations.Ad` | Local user and Active Directory command handlers |
| `src/Cerberus.Agent.Integrations.Tailscale` | Tailscale status and `tailscale.ensure_connected` |
| `src/Cerberus.Agent.Observability` | Redaction (`Sanitizer`) and file logging |
| `src/Cerberus.Agent.Runtime` | Shared files linked into the service, updater and uninstall binaries |
| `src/Cerberus.Agent.Service`, `.Updater`, `.Uninstall` | Entry points |
| `src/Cerberus.Agent.Installer` | WiX MSI |

## Install

### Desktop

1. Run `Cerberus.Agent-<channel>-<version>.msi` and accept the EULA.
2. The last installer page can open the panel (`app\Cerberus.Agent.exe --open`).
3. The panel handles sign-in, registration, portal claim, service install (UAC) and start.

The MSI records EULA consent under `HKLM\Software\Cerberus\WindowsAgent\LegalConsent` (server: `ServerAgent\LegalConsent`); the agent imports it with `acceptedVia = "msi_eula_dialog"`. `--accept-eula` is for support and headless installs only.

### Server

Run `Cerberus.Agent-<channel>-<version>-server.msi` and enter the enrollment proof. The installer runs `--enroll-headless --proof-from-installer <proof> --install-service` as a deferred custom action; no other arguments are accepted. Enrollment runs once, on first install only.

### MSI properties

Non-secret public properties, stored under `HKLM\Software\Cerberus\WindowsAgent` (server: `HKLM\Software\Cerberus\ServerAgent`):

| Property | Default | Profile |
|---|---|---|
| `CERBERUS_BACKEND_URL` | build default | both |
| `CERBERUS_SSO_BASE_URL`, `CERBERUS_SSO_CLIENT_ID` | build default | both |
| `CERBERUS_SSO_SCOPE` | `openid profile email groups` | both |
| `CERBERUS_CHANNEL` | release channel | both |
| `CERBERUS_LANGUAGE` | `auto` (`en-US`, `tr-TR`) | both |
| `CERBERUS_EULA_ACCEPTED` | unset; `1` for approved managed installs | both |
| `CREATE_DESKTOP_SHORTCUT` | `0` | desktop |
| `START_TRAY_ON_LOGIN` | `1` | desktop |
| `CERBERUS_ENROLLMENT_PROOF` | none; hidden, not logged | server |

Do not pass secrets in other MSI properties.

## Backend contract

| Call | Endpoint |
|---|---|
| Register (desktop) | `POST /api/v1/agents/register` |
| Enroll (server) | `POST /api/v1/agents/bootstrap/enroll-headless` |
| Refresh access token | `POST /api/v1/agents/token` |
| Heartbeat, pending commands | `POST /api/v1/agents/{id}/heartbeat` |
| Command ack / result | `POST /api/v1/agents/{id}/commands/{commandId}/ack`, `/result` |
| AD command authority | `POST /api/v1/agents/{id}/commands/{commandId}/ad-authority` |
| Managed account manifest | `GET /api/v1/agents/{id}/managed-accounts/manifest` |
| Telemetry | `POST /api/v1/agents/{id}/snapshot`, `/events`, `/probe-results` |
| Diagnostic bundle | `POST /api/v1/agents/{id}/diagnostic-bundles` |
| Tailscale pre-auth | `POST /api/v1/agents/{id}/tailscale/preauth` |
| Deactivate | `POST /api/v1/agents/{id}/deactivate` |

Every agent request carries a bearer token and a signature:

- `X-Agent-Id`, `X-Nonce` (16 random bytes, hex), `X-Timestamp` (Unix seconds)
- `X-Body-Hash`: SHA-256 of the body, Base64
- `X-Signature`: RSA PKCS#1 v1.5 SHA-256 over `v1:{METHOD}:{PATH}:{NONCE}:{TIMESTAMP}:{BODY_HASH}`, Base64 (path without query)

## Commands

Commands are idempotent per command id (`idempotency.json`, 24 h). Unknown types fail and are cached the same way.

Desktop:

- `agent.health.snapshot`, `agent.rdp.quick_test`, `agent.diagnostic_bundle.collect`, `agent.update.request`
- `tailscale.ensure_connected`: when Tailscale is installed but not connected, runs `tailscale up` with the one-time auth key from the backend. `CERBERUS_AGENT_TAILSCALE_AUTO_UP=0` turns this off.
- `windows.local_user.create`, `.disable`, `.delete`. Local user creation is controlled on the device with `--enable-local-user-create` / `--disable-local-user-create`.
- `windows.ad_user.create`, `.disable`, `.delete`: each command needs a short-lived authority from the backend.

Server: `ping`, `collect_facts` (one telemetry collection), `agent_state`. Server commands arrive in signed envelopes verified against the trust anchors built into the package.

## Telemetry

The service posts a snapshot on the interval the backend returns, within the profile limits, with ±20% jitter.

- Desktop sections: identity, os, resources, network, tailscale, rdp, firewall, security, clock, runtime, capabilities. `CERBERUS_AGENT_TELEMETRY_SECTIONS` can narrow the list.
- Server sections: identity, os, resources, network, firewall, security, clock, runtime, sessions, hardware, services, listening_ports, updates, software, processes.

Server `security` includes failed logons per protocol (RDP, SSH, SQL Server, and other for network and console logons) with an event-log cursor, successful interactive/RDP logons, local administrators and membership changes, log clears, unexpected shutdowns, and Defender/SMBv1 posture. SQL Server failures count only when the event was written by the running SQL Server service process; other entries are reported as `unverified`. Command lines, passwords and attempted user names are not collected.

Snapshots that cannot be sent are buffered in `telemetry-offline.json`; one-time feeds (failed/successful logons, admin changes) are dropped from buffered copies so they are not counted twice.

## Security model

- Secrets (`agent_id`, `tenant_id`, refresh token, agent private key, backend URL, optional Tailscale pre-auth) are DPAPI-encrypted in `secrets.json` in the data directory. The machine-scope file is limited to SYSTEM and Administrators; a user-scope onboarding file also grants the signed-in user.
- Access tokens are refreshed shortly before expiry with the stored refresh token.
- Updates: the manifest is signed with a Cerberus key, and the MSI and binaries must carry an Authenticode signature whose publisher key matches a key pinned at build time.
- Logs pass through `Sanitizer`, which redacts token, secret, password, private key, API key and authorization values, JWT-like strings and Headscale keys.

## Configuration

Environment variables: `CERBERUS_BACKEND_URL`, `CERBERUS_SSO_BASE_URL`, `CERBERUS_SSO_CLIENT_ID`, `CERBERUS_SSO_CLIENT_SECRET` (read from the environment only, never stored), `CERBERUS_SSO_SCOPE`, `CERBERUS_OAUTH_REDIRECT_PORT`. The older `CERBERUS_CASDOOR_ENDPOINT`, `_CLIENT_ID`, `_CLIENT_SECRET` and `_SCOPE` names are still accepted.

`%LOCALAPPDATA%\CerberusAgent\ui-config.json` keeps non-secret UI defaults (backend URL, SSO endpoint, client ID, scope, redirect port).

## Files and logs

In the data directory (`%ProgramData%\CerberusAgent` or `CerberusServerAgent`):

- `secrets.json`, `idempotency.json`, `command-envelopes.v1.json`, `telemetry-offline.json`, `update-plan.json`, `manifest.json`
- `logs\agent.log` (service); the tray writes `logs\agent-ui.log` under `%LOCALAPPDATA%`.

## CLI

Support and automation flags of `Cerberus.Agent.exe`:

- Panel and setup: `--open`, `--connect`, `--setup`, `--onboard`, `--register`, `--accept-eula`
- Service: `--service`, `--install-service`, `--uninstall-service`, `--start-service`, `--stop-service`
- Updates: `--check-updates`, `--update-now`, `--update-check-once`, `--update-apply-once`, `--apply-staged-update <path>`
- Diagnostics: `--self-test`, `--self-test-json`, `--self-test-out <path>`, `--heartbeat-once`, `--export-tailscale-up`, `--show-fingerprint`
- Device: `--unregister-device`, `--factory-reset`, `--enable-local-user-create`, `--disable-local-user-create`
- Server enrollment: `--enroll-headless` with `--proof-stdin`, `--proof-file <path>` or `--proof-from-installer`; `--enroll-rollback`

`--register` uses the browser (PKCE) flow; token-file registration is disabled.

## Development

Requires Windows 10/11 and the .NET 10 SDK.

```powershell
dotnet build src/Cerberus.Agent.App/Cerberus.Agent.App.csproj -c Release
dotnet test tests/Cerberus.Agent.Core.Tests/Cerberus.Agent.Core.Tests.csproj -c Release
```

Server profile: add `-p:AgentBuildProfile=server`. If a `.slnx` command fails locally, use the project files as above.

- `./scripts/preflight.ps1`: build, test, publish and self-test.
- `.\scripts\clean-install-smoke.ps1`: install smoke. Steps that change the machine run only with their switches (`-RunEnrollment`, `-HeartbeatOnce`, `-InstallService`, `-StartService`, `-StopService`, `-UninstallService`); it does not create Windows users.

## Releases

Releases are built by `.github/workflows/auto-publish-exe.yml` (desktop) or `scripts/build-agent-public-release.ps1` (desktop or server). Local builds need PowerShell 7.

Signing (`-SigningMode`):

- `Pfx` (workflow default): `WINDOWS_SIGNING_CERT_BASE64`, `WINDOWS_SIGNING_CERT_PASSWORD` and `AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM`.
- `Token`: a hardware-token certificate selected with `-SigningCertThumbprint`; `-ExtraSignerPins` adds publisher keys that agents also accept, for key rotation. All first-party files are signed in one `signtool` run, then each signature and its publisher pin are checked.

Every first-party binary and the MSI must be signed; only the `dev` channel can build unsigned, with `-AllowUnsignedDevBuild`. Preview and stable server builds refuse the test command trust anchors.

Outputs per build (`<suffix>` is `-server` for server builds):

- `Cerberus.Agent-<channel>-<version><suffix>.msi`
- `Cerberus.Agent.Bundle-<channel>-<version><suffix>.zip`, `.sha256`, `.sbom.json`, `.provenance.json`, `.release-gate.json`
- `.update-manifest.v2.json` (and the v1 manifest where still produced), plus `-latest` aliases

Workflows:

- `ci.yml`: build and test on pushes and pull requests to `dev` and `develop`; manual for other refs.
- `auto-publish-exe.yml`: runs on `dev`/`develop` pushes that touch source or build files, and manually with `release_version`, `channel` (`dev`, `preview`, `stable`) and `release_notes`. Each run creates a versioned release and moves the `<channel>-latest` pointer; stable runs are also marked as the latest GitHub release.

```powershell
gh workflow run auto-publish-exe.yml --ref dev -f release_version=0.2.0-preview.1 -f channel=preview -f release_notes="..."
```

## Troubleshooting

- Registration fails with a configuration error: check `CERBERUS_BACKEND_URL`, `CERBERUS_SSO_BASE_URL` and `CERBERUS_SSO_CLIENT_ID`.
- The service cannot read secrets: the device must be registered in machine scope.
- `tailscale.ensure_connected` fails with exit code 2: the backend has not issued a one-time auth key for this device yet.

## Branches

`dev` is the integration branch; open pull requests against `dev`. `main` changes only by explicit promotion.
