# Windows agent acceptance guide

Read this guide when `../AGENTS.md` routes work here. It holds the detailed
real-path acceptance procedure; the entrypoint keeps the public-agent safety
boundary and evidence contract.

## Scope and approval

Ask first before adding NuGet/system dependencies; changing service
install/start/stop/uninstall, DPAPI/credential storage, enrollment, heartbeat,
telemetry, command protocols, or managed-local-user behavior; signing,
publishing, releasing, deploying, or weakening security. Never commit secrets,
certificates, private keys, tokens, browser state, or generated credentials.
Credential changes are short-lived, scoped, revocable, and auditable. Ambiguous
identity, tenant, resource, assignment, or command state fails closed. Where
applicable, exercise wrong-tenant claim/read, assignment, command enqueue,
credential reveal, and forged result submission.

## Evidence contract

Mocks, fake users/service state/telemetry, synthetic rows, and mocked portal/API
routes are support evidence only. A public-agent behavior crossing the runtime
chain normally needs: built executable/service; configured current auth path;
real backend; persisted DB write/read; real portal/API projection; and actual
Windows service and local-user lifecycles when touched. `Connected` is not
acceptance: verify registration, install/running state, heartbeat, persisted
snapshot, projection, command readiness/result, cleanup, and uninstall
separately. Prove one intended real boundary before repeating; choose repeats
from blast radius/release criteria and fix bootstrap root cause before counting.

Reference, do not paste, installer/service logs and binary identity, self-test,
backend/API and persisted state, lifecycle status, readiness/result, browser or
Playwright artifacts tied to the same backend state, and cleanup/residual state.
Never inspect cookies, localStorage, passwords, or profile secrets. Missing
credentials, privileges, backend/DB, portal, or runtime is an explicit blocker,
not an acceptance claim.

## UI, commands, handoff

Use Computer Use only for real desktop-only evidence (installer/tray/enrollment,
service UI, permission prompts, GUI-only failures); prefer deterministic
PowerShell, service status, logs, exit codes, and repo-native tests. Keep one
visible flow and stop for credential, admin, security, network, privacy,
destructive, or credential-revealing prompts unless authorized. Use Browser/
Chrome first for web UI.

Inspect current scripts before selecting commands. Baseline entry points are:

```text
dotnet test tests/Cerberus.Agent.Core.Tests/Cerberus.Agent.Core.Tests.csproj -c Release
.\scripts\preflight.ps1
.\scripts\clean-install-smoke.ps1 -RunEnrollment
```

Report exact commands, evidence tier, real boundary, repeat count, artifacts,
and required real checks that did not run. Unit/fake tests remain support
evidence; an open required check means acceptance is incomplete.

## Self-update recovery acceptance

This procedure implements the canonical Windows-agent self-update rule in
`F:/cerberus-repos/AGENTS.md`, Evidence section (user
decision 2026-11-04). Apply the same rule to every deployment using this agent and update path.
The rule applies after any change that can affect updates, including the
updater, manifest/feed, packaging, service lifecycle, and version/channel logic.
Keep the acceptance requirement in that canonical rule; this section owns its
detailed execution and evidence procedure.

Final acceptance requires at least **10 consecutive
successful, unattended updates to distinct newer versions on each of the owner
PC and VM106** (at least 20 successes). Use one frozen functional candidate and
10 version variants; record the source head and each package hash. A functional
source change resets acceptance for the final candidate. Report bootstrap
separately; installing the initial test candidate is not a successful transition.

Every counted transition must include a controlled fault at the real agent or
update boundary and recover automatically through the installed agent's normal
updater. Select safe injection points from the actual source/runtime before
starting. Examples include a transient manifest error, timed-out request,
malformed manifest, truncated or hash-mismatched artifact, rate limiting,
interrupted agent/updater at a recoverable pre-installer boundary, stale or
duplicate notification, and lost post-install acknowledgement. A simulated
unit response is support evidence and cannot prove this runtime acceptance.

Do not count manual MSI installation, panel clicks, command resubmission,
manual service recovery, duplicate notifications, retries to the same already
installed version, or a terminal/half-installed result as a successful update.
Stop advancement if recovery fails; preserve logs, counters and the last known
healthy artifact, fix the cause, then restart acceptance on the final candidate.

For each target and transition record sanitized stable target identity,
candidate/source, from/to versions, package hash, injected fault and timestamp,
actual updater/installer result, retry/recovery events, restored connection and
version, zero manual interventions, and target health. Observe that RDP/Tailscale
remain unaffected; do not alter their configuration or use route, portproxy,
firewall or adapter changes as a test workaround. Do not automatically reboot
the owner PC. Identity keys and other production services are outside the fault
scope and must remain untouched. Coordinate feed and collector changes with OPS.

The development test window is limited to these two explicitly authorized
targets and their separate test candidate/feed. It does not authorize an
unsigned public release or a 40-server rollout. TLS, package hash, enrollment,
authorization, audit and rollback remain enforced. Any authorized temporary
signature exception must remain limited to that test window, be reported in
the evidence, and cannot certify the production signing/trust path. Keep final
exact-head review, merge and release gates separate from test acceptance.

### Preparing and running the two-target test campaign

Resolve the enrolled wire identity to the backend's durable registration before
writing the public campaign policy. Do not infer `AgentId` or
`TenantId` from DB column names: prove the API mapping to host/registration and
the registered public-key fingerprint. Hostnames and source IPs are observation
and routing evidence, not authority. Preserve the existing enrollment keys.

The compiled `agent.update.lab.v1` policy contains exactly two wire-identity /
public-SPKI bindings, separate HTTPS manifest URIs and artifact prefixes under
`/updates/devtest/`, eleven increasing versions (bootstrap plus ten targets),
the approved existing backend/SSO URLs, and a UTC window of at most 48 hours.
It is active only with the server profile, `dev` channel and explicit unsigned
dev flag. Normal builds omit the metadata. Lab trust accepts only its embedded
manifest key and selected target URI/prefix; registry/environment overrides do
not extend it. The feed root belongs to the update HTTP handler, not the OS
certificate store or the general backend trust set. Record SYSTEM/BITS results
separately; a successful OpenSSL or .NET probe alone does not prove BITS trust.

`scripts/build-agent-test-campaign.ps1` takes a clean exact source head and
public policy/root/command/backend-anchor files. It preserves one memory-held
RSA manifest key across all eleven versions, writes no private-key file, keeps
existing output directories, freezes public input hashes, and records package
and per-target manifest hashes. Unsigned MSI payloads use the existing dev
exception; RSA manifest signatures, hash/length, enrollment and runtime guards
remain enforced. Default candidate checks run once; later version variants
reuse unchanged functional evidence. If `-SkipTests` is used, identify the
existing exact-candidate checks and every missing check in the delivery report.
The builder does not upload or install. Route the final candidate and public
policy/artifact evidence through the required independent/security review
before bootstrapping either live target.

The service admits a compiled local campaign request through the existing
durable scheduler path; it does not manufacture a signed command. The receipt
retains policy identity, enrollment generation, verified release, deadline and
bounded retry count. Repeated polls cannot reset an exhausted request. Quarantine,
pending revocation/state delivery, expiry and the final launch fence still apply.
Expiry blocks new admission/launch while existing installer reconciliation and
rollback retain their normal path.

OPS advances only the isolated files on the existing WAN collector path after
both targets complete the preceding version and recovery, with zero human
recovery. No collector faults, new listener, firewall, proxy or network changes.
Transitions 1–7, 9 and 10 exit the service after a durable staging start;
transition 8 exits the updater after artifact verification and before installer
handoff. Each version
has its own protected once receipt. Receipts prove arming only; prove process
exit/SCM restart, resumed update, backend report receipt and ordinary retry from
runtime evidence. Do not advance after failed recovery or count the bootstrap.

The lab-only BITS callback validates the actual connection leaf against the
selected collector root and SAN before the HTTP request, with OS name/date/usage
checks retained and redirects disabled. Completion requires an observed callback
and protected `bits-tls.json`; unit/direct-callback checks are support evidence.
No callback support means failure, never a weaker fallback or OS-root import.

MSI admission runs in the existing SYSTEM bootstrap action before StopServices.
The updater first flushes a unique transaction grant inside its launch fence;
the zero-count bootstrap instead requires a fresh, unexpired two-target grant.
Later runtime/health checks verify that admission with the same product,
transaction, enrolled identity/key/generation, policy and compiled payload
hashes. Expiry cannot renew admission or interrupt that transaction's existing
completion. Successful MSI commit consumes admission; health success alone does
not. A protected campaign/device ledger permits one bootstrap from that target's
explicit `bootstrapSourceVersion`. Rollback retires only its pending transaction;
committed state is retained, and ambiguous pending state blocks another bootstrap.
Every counted admission requires the immediate successor of the installed source
version before sequence acceptance, request, launch and MSI handoff. Current-version
polling creates no request and does not advance the sequence floor. The protected
plan and MSI launch grant retain the predecessor captured before files change;
the incoming helper's own version is never used as the installed predecessor.
Desktop service-install and normal preview/stable signature checks stay intact.

Before freezing versions, reserve eleven increasing lab versions below the
existing signed return MSI's version. The incoming dev bootstrap permits that
one preparatory downgrade; its ten counted transitions must then increase.
Return through the same server MSI major-upgrade path, preserving enrollment,
protected state and sequence floors. Do not uninstall/re-enroll or clear replay.
The historic signed manifest can remain below the campaign sequence floor:
normal binaries/heartbeat restoration and future normal-feed continuity are
separate evidence. Continuity needs a genuinely signed higher-sequence normal
manifest; do not claim it from restoring binaries alone.
