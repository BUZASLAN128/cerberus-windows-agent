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
scope and must remain untouched. Coordinate test feed and backend changes with
their operators.

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
`-PackageCount 5` builds only the first five packages (trial campaign); a
counted campaign needs all eleven. The builder writes
`campaign-artifacts.json.sha256` for the launcher. It does not upload or
install. Route the final candidate and public policy/artifact evidence through
the required independent/security review before bootstrapping either live
target.

The service admits a compiled local campaign request through the existing
durable scheduler path; it does not manufacture a signed command. The receipt
retains policy identity, enrollment generation, verified release, deadline and
bounded retry count. Repeated polls cannot reset an exhausted request. Quarantine,
pending revocation/state delivery, expiry and the final launch fence still apply.
Expiry blocks new admission/launch while existing installer reconciliation and
rollback retain their normal path.

The runner, not an operator, advances the isolated test feed.
`scripts/campaign/start-update-campaign.ps1` (elevated) copies the runner and
`campaign-lib.ps1` from the frozen commit, and the config, campaign artifacts,
hold MSI, feed root and pinned tools into a SYSTEM/Administrators-only folder
under ProgramData. It checks every SHA-256 pin, proves a restricted token cannot
write there and starts `invoke-update-campaign.ps1` from that folder. The runner
publishes the next version only after the agent's journal shows the previous one
installed, produces the hop's fault, waits for the agent's own recovery and
records the hop. It reads only the agent's local records and the test feed; read
the backend's version and last-seen time at the start and end of each campaign.
It stops at the first failure and never retries; a started step never runs
again. No backend faults, new listener, firewall, proxy or network changes.
`scripts/campaign/campaign-config.example.json` lists the inputs.

| Counted transition | Fault | Produced by | Expected recovery |
| --- | --- | --- | --- |
| 1, 7 | Windows Installer busy (1618) | Runner: the hold MSI keeps the installer busy until the agent records 1618, then fails and rolls back | Agent retries and installs |
| 2, 4 | Truncated artifact | Feed serves a short file; the runner restores the full file after the agent rejects it | Download rejected, retried after 30 s, installs |
| 3 | Service killed while the journal shows `health_pending` | Runner, by the service's process id | Service restarts, journal turns `installed`, the next hop installs |
| 5, 8, 10 | Service exits after durable staging starts and before download | Campaign code in the agent | Service restarts and resumes the update |
| 6, 9 | Updater exits after artifact verification and before installer handoff | Campaign code in the agent | Agent retries and installs |

Transitions 1–4 carry no in-agent fault. In-agent faults keep a protected once
receipt per version; receipts prove arming only, so prove process exit, service
restart, resumed update and backend contact from runtime evidence. If the trial
shows 1618 cannot be produced, transitions 1 and 7 use a truncated artifact and
the report keeps "1618 not verified" open. If the runner misses the transition 3
window, that hop proves only a service crash and restart and is recorded as such.

Before the counted campaign, an uncounted trial campaign (eleven versions, five
packages) runs its own bootstrap and three hops: D1 installer busy (1618), D2
truncated artifact, D3 the new service killed inside the 120-second server health
window. D3 passes only when the install fails (1603), Windows restores the
previous version and the agent reaches the backend again with the same
enrollment; hop 4 repeats D3 once if the kill missed. A failed D1–D3 recovery is
a product or harness defect to fix before the counted campaign. The counted
campaign is a new campaign with its own bootstrap, built after the trial so its
versions and sequences are higher.

The lab-only BITS callback validates the actual connection leaf against the
selected feed root and SAN before the HTTP request, with OS name/date/usage
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
The scheduler and lab trust admission wait for bootstrap commit before the first
counted update, so its controlled service interruption cannot break bootstrap health.
Every counted admission requires the immediate successor of the installed source
version before sequence acceptance, request, launch and MSI handoff. Current-version
polling creates no request and does not advance the sequence floor. The protected
plan and MSI launch grant retain the predecessor captured before files change;
the incoming helper's own version is never used as the installed predecessor.
Desktop service-install and normal preview/stable signature checks stay intact.

Reserve increasing versions above every installed version. Use this order for
each target: installed version, trial bootstrap, trial hops D1–D3 (and the
spare), counted bootstrap, counted targets 1–10, signed return R. Each policy
binds its starting installed version through `bootstrapSourceVersion`. Use a
separate campaign GUID and host state for each campaign.

Initialize each test feed at the first updater-driven successor. The MSI
bootstrap's committed ledger gates that first hop, which supplies the updater
and backend evidence for subsequent feed progression. The owner signs R at the
next multiple of 10 above all campaign and installed versions.
Return through the same server MSI major-upgrade path, preserving enrollment,
protected state and sequence floors. Do not uninstall/re-enroll or clear replay.
The historic signed manifest can remain below the campaign sequence floor:
normal binaries/heartbeat restoration and future normal-feed continuity are
separate evidence. Continuity needs a genuinely signed higher-sequence normal
manifest; do not claim it from restoring binaries alone.
