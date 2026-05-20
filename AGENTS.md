# Cerberus Windows Agent Instructions

These rules apply under `cerberus-windows-agent/`. The root `AGENTS.md`
execution contract still applies.

## Scope

This repo owns the public Windows agent/service, enrollment, telemetry,
commands, managed-user behavior, update/uninstall flows, and related tests.

Applied Guardrail: public Windows agent - real-path acceptance is never
mock-complete.

## Ask First

Ask first before adding NuGet/system dependencies, changing service
install/start/stop/uninstall behavior, changing DPAPI/credential storage,
changing heartbeat/telemetry/command protocols, changing managed local user
behavior, signing/releasing/deploying, or weakening security posture.

Never commit secrets, certificates, private keys, tokens, local auth state, or
generated credentials.

Do not introduce static admin/shared credentials or persistent standing
privilege as the default agent model. Prefer short-lived, scoped, revocable
credentials/tokens when credential flow changes are explicitly approved.

## Acceptance Standard

Public Windows agent work has a stricter bar than normal unit/API work. Mocked
agent clients, mocked browser routes, mocked portal API responses, fake local
users, fake service state, fake telemetry, and synthetic "connected" rows are
not acceptance evidence.

Completion evidence must exercise the real chain unless the user explicitly
scopes the task to a pure unit helper:

- real built agent executable or service binary,
- real Casdoor/PKCE or current configured auth path,
- real backend endpoint,
- real database write/read for persistent state,
- real portal page or API response without mocked data,
- real Windows service install/start/stop/uninstall when service behavior is
  under test,
- real Windows local user create/disable/delete when managed-user behavior is
  under test.

Unit tests with fakes are allowed only as support evidence for pure functions,
schema validation, negative-path policy checks, and fast development. Label
them as support; do not report them as "agent ready", "real-use accepted",
"live accepted", or "customer-ready".

## Repeated Run Rules

- `1x` is a smoke check only for public agent work.
- Minimum completion evidence is `5x` over the same real-path boundary being
  claimed.
- Final close evidence is `10x` over the same real-path boundary.
- Do not run long `5x`/`10x` loops over mock-only suites. First prove the suite
  is real-path.
- If the first iteration fails on environment/bootstrap, stop the repeat loop,
  fix the root cause, and restart the count. Do not count setup failures as
  resilience evidence.

Each repeated run should produce a compact table:

- iteration,
- real boundary exercised,
- pass/fail,
- duration,
- artifact path,
- failure root cause when present.

## Required Artifacts

Real-use acceptance must produce or reference:

- installer/service logs,
- agent self-test JSON,
- portal API JSON,
- DB query output for persisted telemetry,
- Playwright screenshot/trace of the real portal,
- Windows verification output for service/user state.

"Connected" is not proof by itself. Acceptance must separately verify
registration state, service installed, service running, heartbeat time,
snapshot persisted, portal display, command readiness, and cleanup/uninstall
state.

## Live Evidence Checklist

For live acceptance, record exact command output or artifact paths for the
checks that match the claim:

- built agent executable or service binary identity,
- install/start/stop/uninstall service state when service behavior is touched,
- heartbeat time and persisted snapshot state from backend/database evidence,
- portal page or API projection without mocked `route.fulfill()` data,
- command readiness and command-result persistence,
- managed local user create/disable/delete state when user management is
  touched,
- cleanup/uninstall state and any residual service/user/file artifacts.

## Acceptance Commands

- Use repo-native build, service, self-test, and acceptance scripts from this
  repository after inspecting the current scripts/tests. Do not invent command
  names from memory.
- Verified baseline commands:
  - `dotnet test tests/Cerberus.Agent.Core.Tests/Cerberus.Agent.Core.Tests.csproj -c Release`
  - `.\scripts\preflight.ps1`
  - `.\scripts\clean-install-smoke.ps1 -RunEnrollment`
- If the exact acceptance command is unclear, inspect the build/test files
  first, then run the smallest real-path command that proves the boundary.
- Report the exact command, repeat count, real boundary exercised, and artifact
  path. Label pure unit tests with fakes as support evidence only.

## Cross-Tenant and Abuse Tests

Agent security/tenant tests must use real backend authorization and
tenant-scoped persistence. Attempt wrong-tenant:

- claim,
- projection/detail read,
- assignment,
- command enqueue,
- credential reveal,
- fake command-result submission where applicable.

Fail closed on ambiguous identity, tenant, resource, or assignment state.

## Execution Discipline

- Keep status updates short during long runs.
- Preserve bulky evidence as artifacts and reference paths instead of pasting
  logs into chat.
- Separate one-time bootstrap from repeated assertions where safe, but do not
  replace the real boundary with mocks.
- If credentials, Windows service access, DB access, or portal access are
  unavailable, state the exact blocker and do not claim acceptance.
