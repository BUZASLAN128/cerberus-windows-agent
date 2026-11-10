# Cerberus Windows Agent Instructions

These rules apply under `cerberus-windows-agent/`. The root `AGENTS.md`
execution contract still applies.

## Scope

This repo owns the public Windows agent/service, enrollment, telemetry,
commands, managed-user behavior, update/uninstall flows, and related tests.

Applied Guardrail: public Windows agent - real-path acceptance is never
mock-complete.

## Work Rules

Owner decision 2026-11-10, written by Claude and Codex. For two days the owner
read "merged and signed" as "agent OK", while the 10+10 self-update acceptance
had not started. These rules keep "done" and the reported status honest.

1. Finished means built and checked unsigned. When a piece of agent work is
   finished, build an unsigned dev MSI from that exact head
   (`scripts/build-agent-public-release.ps1 -Channel dev -AllowUnsignedDevBuild`,
   the touched profile, both for shared code; check its current parameters)
   and install it the same day on the test VM as an upgrade over the version
   deployed there: service running, enrolled identity kept, heartbeat on the
   backend, one panel command ACKed, and for update code one update plus its
   failure recovery. Record head, MSI hash and results. (#94's release gate
   blocked every non-lab server build; it surfaced only at the 0.2.1014
   release build, fixed in #95.)
2. Sign only what passed. The signing session uses a candidate whose unsigned
   check passed on the same head; never sign to find out whether a build works.
   A signed build agents refuse burns a manifest sequence (0.2.1008, 257 MB MSI
   over the 200 MiB download cap).
3. Test the field path. Upgrade from the version actually installed in the
   field, not only fresh installs (1009+ single-file MSIs failed with 1603 on
   every older install). Before calling a feed ready, fetch the published
   manifest's own `artifact_url` from an off-LAN agent (1009-1011 pointed at
   an internal address).
4. Status line on every report. Each agent status to the owner starts with:
   merged (head) / unsigned check (date, target) / signed (MSI hash) / 10+10
   self-update (count per target) / published (channel). Say "agent OK" only
   when every required stage is done; otherwise name the missing stage. A
   merge, a valid signature or a running service is not acceptance.
5. Own evidence only. A test passed only when the target's own receipts and
   logs show it, never from another session's transcript or one observation
   (VM106 10/10 claim taken from another transcript; wakeup "works" from one
   ping).
6. Product and harness apart. Report test-harness or campaign work separately
   from product changes: "agent unchanged since <head>; test setup in review".
7. Green CI is not a build. Build steps must fail on errors, and the release
   gate must run on a non-lab build before merge (#80 reached dev not
   compiling because CI ignored exit codes).
8. No release on dev pushes. Before merging, confirm no workflow publishes or
   moves dev-latest on a dev push (auto-publish-exe.yml published
   v0.2.154-dev.154).
9. Leave real machines clean. Unit tests never write to real ProgramData paths
   (a planted `ui-context.json` broke the 1005 install with 1722). Remote/QGA
   helpers use unique Verb-Noun names, checked for alias collisions (a helper
   named `Rd` deleted VM106 receipts).
10. A failure shows its cause. Every failed update or install state carries an
    error code in the agent status (#94: an expired manifest showed as failed
    with no code).

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
- Playwright screenshot/trace or Codex Chrome plugin screenshot/DOM/console
  evidence of the real portal,
- Windows verification output for service/user state.

"Connected" is not proof by itself. Acceptance must separately verify
registration state, service installed, service running, heartbeat time,
snapshot persisted, portal display, command readiness, and cleanup/uninstall
state.

## Windows Desktop Visual Verification

Use Computer Use when Windows agent work depends on the real Windows GUI:
installer screens, tray/app windows, enrollment dialogs, service-control UI,
permission prompts, visible error states, or a bug that only reproduces in the
desktop interface.

Computer Use is visual evidence, not the default replacement for deterministic
checks. Prefer PowerShell, service status, logs, repo-native tests, installer
exit codes, and source inspection for repeatable validation. Pair Computer Use
evidence with the matching non-GUI command, log, or test whenever feasible.

When using Computer Use on Windows:

- Keep the target app visible on the active desktop.
- Scope the task to one app, window, or flow at a time.
- Stay present for credential, administrator, security, network, or privacy
  prompts.
- Do not approve destructive, credential-revealing, or system-wide changes
  without explicit user approval.
- Record evidence: app/window tested, visible state observed, and matching
  command/log/test artifact when available.

For local web UI checks, use Browser/Chrome first. Use Computer Use only when
the required evidence is outside the browser or depends on the Windows desktop.

## Live Evidence Checklist

For live acceptance, record exact command output or artifact paths for the
checks that match the claim:

- built agent executable or service binary identity,
- install/start/stop/uninstall service state when service behavior is touched,
- heartbeat time and persisted snapshot state from backend/database evidence,
- portal page or API projection without mocked `route.fulfill()` data,
- Chrome plugin live portal evidence when it improves local debugging speed,
  tied to the same real backend/API/DB state being claimed,
- command readiness and command-result persistence,
- managed local user create/disable/delete state when user management is
  touched,
- cleanup/uninstall state and any residual service/user/file artifacts.

Use the Codex Chrome plugin for fast local live portal validation when the
user's real Chrome profile, open tabs, existing login state, DOM, screenshot,
or console output is useful. Playwright remains canonical for CI, repeatable
scripted gates, and `5x`/`10x` close evidence. Do not inspect browser cookies,
localStorage, passwords, profile secrets, or session stores, and close
agent-created temporary Chrome tabs after the check.

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
