# Managed commands and heartbeat delay

The transport candidate does not move managed local-user or AD commands to the
generic asynchronous executor. They retain their existing synchronous authority,
lease and reconciliation paths and may delay heartbeats. This is a known
limitation, including when generic asynchronous commands are enabled.

The lifecycle lock binds a local mutation to an enrollment generation. The
managed-account manifest gate serializes authority refresh, account mutation and
compensation. An AD command additionally checks the exact lease and fresh
server authority, then retains its lifecycle fence while it executes and may
disable an account when activation expires. A process or task timeout does not
prove an already-dispatched directory operation cannot finish later. Moving
these operations requires a durable, identity-bound recovery protocol that
handles this uncertainty, revoke, re-enrollment and late results; it must be
validated with a controlled AD environment before enabling it. No such managed
async feature is enabled by this candidate.

The locally inspected Cerberus backend snapshot `16af89fa01ad6f581e7e8eff04ad998ec66f5c4e`
also contains an AD lease-recovery branch that can requeue an expired command
while attempts remain and the desired intent is current. A remote directory
operation can have an unknown outcome when a lease expires; safe decoupling
therefore needs coordinated backend and agent reconciliation and duplicate
execution analysis. This is a source observation, not proof of a live retry or
an incident. Neither backend retry behavior nor managed execution was changed.

## Optional local observation

`CERBERUS_MANAGED_DELAY_DIAGNOSTIC=1` enables a best-effort warning after a
managed local-user or AD command has been pending for 60 seconds. It is disabled
when unset or set to any other value and applies to the primary Desktop service
only. The timer covers the command's acknowledgement, execution and result
submission, so the warning is evidence of a slow command path, not proof that a
specific account operation blocked. It contains no command ID, account name,
tenant ID or payload. The warning does not cancel, retry or change authority.
It cannot report a stall in manifest refresh before command dispatch, or warn
after a process has stopped. A logging failure is ignored. Local logs reach a
fleet operator only if the existing log collection is configured separately;
this change adds no automatic remote notification.

The backend's existing portal projection can show `stale` or `unreachable` when
the last recorded heartbeat ages past its configured thresholds. These states
can also mean network failure, service shutdown or another cause. Presence may
use cached data and the database update is normally throttled, so it is not a
precise 60-second managed-command alarm; no first heartbeat also means no elapsed
heartbeat measurement. Correlate the local warning and the server observation
before attributing cause. Removing the setting on the next authorized service
restart disables the local diagnostic without changing command semantics.
