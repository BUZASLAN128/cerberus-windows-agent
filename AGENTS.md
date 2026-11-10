# Cerberus Windows Agent Instructions

These rules apply under `cerberus-windows-agent/`. The root `AGENTS.md`
execution contract still applies.

## Scope

This repo owns the public Windows agent/service, enrollment, telemetry,
commands, managed-user behavior, update/uninstall flows, and related tests.

Applied Guardrail: public Windows agent - real-path acceptance is never
mock-complete.

## Work Rules

Owner decision 2026-11-10, merged from separate lists by Claude and Codex. For
two days the owner read "merged and signed" as "agent OK" while the 10+10
self-update acceptance had not started. These rules keep "done" and the
reported status honest. Order: code -> official unsigned build -> VM106 smoke
-> final reviews and signing -> 10+10 on the frozen candidate -> normal return
and feed continuity -> publication with the owner's approval.

1. Finished means built unsigned. When agent code, packaging or release
   tooling work is finished, build that exact head through the official
   non-lab pipeline, helper, MSI and setup, for every affected profile (Bilnex
   uses server; both for shared code):
   `scripts/build-agent-public-release.ps1 -Channel dev -AllowUnsignedDevBuild`
   (check its current parameters). Lab or support builds do not count. (#94's
   release gate blocked every non-lab server build; it surfaced only at the
   0.2.1014 release build, fixed in #95.)
2. Smoke it on VM106 the same day, never first on the owner PC. Install it as
   an upgrade over the deployed version and check the installer exit code, the
   installed and running service version, enrollment kept, a fresh heartbeat,
   the persisted backend/API projection and one panel command ACKed. Keep
   enrollment, identity keys, protected history and sequence floors; uninstall
   or clean up only in disposable test state. No safe VM state means the smoke
   is reported blocked. A process, a "Connected" label or a green build is not
   a pass. Record head, MSI hash and results.
3. Prove one real update before repeating. For update-affecting work, run one
   unattended update and its failure recovery through the existing dev trust
   path. Unsigned testing never disables signature, channel or replay checks;
   label lab routes. Final acceptance stays the root AGENTS.md 10+10 rule:
   bootstrap and manual return never count, and changed update behavior is
   proved again.
4. Earn the signing session. The owner signs only a candidate whose unsigned
   build and VM smoke passed on the same head, with inputs and recovery plan
   frozen; never sign to find out whether a build works (0.2.1008, a 257 MB
   MSI over the 200 MiB download cap, burned a manifest sequence). Signing,
   merge and publication stay separate approvals.
5. Test the field path. Upgrade from the version actually installed in the
   field, not only fresh installs (1009+ single-file MSIs failed with 1603 on
   every older install). Before calling a feed ready, fetch the published
   manifest's own `artifact_url` from an off-LAN agent (1009-1011 pointed at
   an internal address).
6. Bind source to what runs. Check that the merged tree is in the artifact
   (ProductVersion, profile, channel), then bind manifest -> MSI URL, size,
   hash and signature -> installer result -> running binary -> backend result.
   A version number, a branch or an HTTP 200 proves none of it (1013 predates
   #94).
7. Status line on every report. Each agent status to the owner starts with
   head and build / VM smoke / signing / PC n/10 / VM n/10 / normal return and
   feed / publication, each PASS, FAIL or NOT RUN, plus the blocker and who
   acts next. Say "agent OK" only when every applicable stage passed. A merge,
   a valid signature or a running service is not acceptance.
8. Own evidence only. A test passed only when the target's own receipts and
   logs show it, never from another session's transcript or one observation
   (VM106 10/10 taken from another transcript; wakeup "works" from one ping).
9. Product and harness apart. Report harness or campaign work separately:
   "agent unchanged since <head>; test setup in review". A harness fix needs
   its own focused check; it neither accepts the product nor requires
   rebuilding unchanged MSIs, and documentation changes do not restart
   product acceptance. Fix the first failing real boundary before adding
   support tests.
10. Protect the execution chain. Privileged or credentialed scripts start from
    a trusted entry, live in protected folders that cannot be renamed, and
    execute the same bytes they verified; no hash-then-reread from a writable
    Temp. Prove the restricted-token denial before launch (G1 findings on
    campaign 6911411 v1 and v2).
11. Check readiness before a one-shot clock. Before a timed campaign starts,
    both targets, owner access, feed inputs and the signed return are ready,
    and uploads, reviews, canary, observers and return fit one budget. Never
    reset an expired invocation or reuse failed receipts (campaign 6911411:
    T+140/T+150/T+200, 410 min).
12. Green CI is not a build. Build steps fail on errors, and the release gate
    runs on a non-lab build before merge (#80 reached dev not compiling
    because CI ignored exit codes).
13. No release on dev pushes. Before merging, confirm no workflow publishes or
    moves dev-latest on a dev push (auto-publish-exe.yml published
    v0.2.154-dev.154).
14. Leave real machines clean. Unit tests never write to real ProgramData
    paths (a planted `ui-context.json` broke the 1005 install with 1722).
    Remote/QGA helpers use unique Verb-Noun names checked for alias collisions
    (a helper named `Rd` deleted VM106 receipts).
15. A failure shows its cause. Every failed update or install state carries an
    error code in the agent status (#94: an expired manifest showed as failed
    with no code).
16. One owner, final reviews once. Keep the existing code-and-test owner and
    unrelated dirty work; run required exact-head reviews once on the
    validated candidate and reuse evidence while its inputs are unchanged.
    More reviewers or repeated green checks never replace the first missing
    runtime result.

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
