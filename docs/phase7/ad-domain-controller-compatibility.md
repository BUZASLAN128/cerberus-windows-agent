# AD and Domain Controller Compatibility

Date: 2026-09-08

This note records the current Cerberus Windows Agent boundary for Active Directory and Windows local account commands.

## Current behavior

- `windows.local_user.create`, `windows.local_user.disable`, and `windows.local_user.delete` are local SAM account commands.
- On Windows domain controllers, local SAM account mutation is not supported. The agent checks `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType`; `LanmanNT` is treated as a domain controller.
- When the machine is a domain controller, local user commands fail closed with `FAILED` and post-verify code `local_accounts_unsupported_on_domain_controller`.
- Service mode registers `windows.ad_user.create`, `windows.ad_user.disable`, and `windows.ad_user.delete` through the scoped native AD provider. Legacy `ad.user.*` handlers are not registered.
- AD is disabled unless a protected, identity-bound local policy explicitly enables a scope. It requires LocalSystem on a domain member workstation/server, never a domain controller or standalone host. Local SAM behavior remains separate.
- Each execution fetches signed backend authority for the current command lease, binds the tenant/agent and lifecycle generation, and expires within 30 seconds. AD never trusts or writes the general idempotency cache.

AD acknowledgments and results echo the exact delivered lease. Execution starts
only after acknowledgment succeeds; a result from an earlier lease cannot finish
a newly leased command. Deploy the matching Windows client before enabling the
backend's required AD lease check. Older clients that omit the lease are rejected
for AD commands; non-AD command bodies retain their existing contract. This
compatibility order is deployment guidance, not evidence that a rollout occurred.

## Explicit opt-in and delegation

An administrator must independently verify exact-OU, user-class-only delegation for this member machine account: create user children, reset passwords, update only required account attributes, and delete owned user leaves. Do not grant group/OU modification, ACL changes, domain-wide user control, or membership in privileged groups. The agent never grants these permissions. Acknowledgments are administrative attestations, not an automatic effective-ACL proof.

Install the following JSON shape at `%ProgramData%\CerberusAgent\Privileged\DirectoryUsers\policy.json`, replacing every example identifier with the verified tenant, enrolled agent, domain, OU, and member-machine identifiers:

```json
{
  "schema_version": "agent.ad-scope-policy.v1",
  "enabled": true,
  "tenant_id": "<tenant-id>",
  "agent_id": "<agent-id>",
  "scopes": [{
    "scope_id": "<scope-uuid>",
    "controller_fqdn": "dc.example.test",
    "domain_guid": "<domain-object-guid>",
    "ou_guid": "<ou-object-guid>",
    "domain_dns_name": "example.test",
    "machine_account_sid": "<member-machine-account-sid>",
    "exact_ou_delegation_acknowledged": true,
    "no_broad_directory_privileges_acknowledged": true
  }]
}
```

The file and containing protected tree must be locally provisioned with ownership and write permissions limited to SYSTEM/Administrators, with no untrusted write inheritance or reparse points. Follow the same protected-path rules as the agent updater; existing unsafe paths are rejected, not repaired into trust. Provisioning is an explicit administrative action, not performed by the validation script. Preserve ownership records during upgrades and reenrollment; deleting them prevents safe adoption/replay.

Before provisioning, run the read-only schema check with PowerShell 7.4+ and trusted built assemblies:

```powershell
./scripts/test-ad-scope-policy.ps1 -PolicyPath <candidate.json> -AgentBuildDirectory <built-agent-directory> -TenantId <tenant-id> -AgentId <agent-id>
```

This invokes the canonical policy decoder but does not contact AD, install anything, or certify delegation. The running provider reloads policy on every operation. Removing/disabling policy blocks subsequent AD operations, including cleanup; disable managed users through the approved flow before withdrawing delegation or policy.

## Credential and object lifecycle

`windows.ad_user.create` has two phases: `prepare` creates a disabled owned user and persists only a tenant-encrypted RDP envelope before initializing its generated password; the backend persists that envelope and sends `activate` with the credential profile plus expected object GUID/SID. Preparation replay returns the same envelope and never resets an initialized password for a different request/profile. A crash before initialization is durably confirmed can reset only the same still-disabled owned user. No plaintext password or private tenant key is stored in ownership records.

Activation requires an unexpired prepared credential and matching durable object/profile. Disable records a monotonic disable intent. Delete requires explicit confirmation, reason, expected GUID/SID, and a disabled owned leaf. Missing ownership or username collisions cannot be adopted. Every native mutation rechecks GUID/SID, parent OU, username, protected-account indicators, and transitive privileged group membership; LDAP uses pinned-controller Kerberos signing/sealing with no referrals or automatic reconnect replay.

AD has no verified atomic guard here against a concurrent trusted administrator moving or promoting an object between the final check and mutation. Exact-OU delegation remains the external enforcement boundary; live acceptance must test that boundary and document the trusted-administrator concurrency limitation. A lost response or timeout can have an uncertain outcome and must not be reported as success. Activation authority expiry triggers a scoped disable attempt and reports failure, with uncertainty if compensation fails.

## Acceptance gap

Support tests cover command authority, protected replay contracts, encrypted credential round trips, native request guards, and local-user fail-closed behavior. They do not prove real Active Directory behavior. Without a domain lab, record `SKIPPED_NO_DOMAIN_LAB` and leave AD acceptance open.

Before closing AD/DC readiness for production, run a live matrix on controlled Windows hosts:

- workstation not domain-joined;
- member server or workstation domain-joined;
- domain controller.

For each host, capture command result persistence, local user state, AD state, portal status, and cleanup evidence. Do not treat mock handlers or registry-only unit tests as public-agent acceptance.
