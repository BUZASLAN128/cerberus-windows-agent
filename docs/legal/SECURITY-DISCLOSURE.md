# Cerberus Windows Agent Security Disclosure

Document version: `agent-security-2026-05-23.v1`

This disclosure summarizes the security-relevant behavior of the Cerberus Windows Agent for deployment review.

This document is a product/security draft and should be reviewed before public production distribution.

## 1. Trust Model

The agent trusts only the configured Cerberus control plane and the local Windows security boundary. It should not grant access when registration, identity, command authorization, or resource assignment is ambiguous.

## 2. Installation and Consent

The agent requires acceptance of the current EULA, Privacy Notice, and Security Disclosure before registration or service installation. The acceptance record contains document versions, timestamp, Windows user, machine name, and acceptance source.

## 3. Local Credential Storage

Agent credentials are stored with Windows DPAPI:

- user-scope during onboarding;
- machine-scope for the Windows service;
- promoted from user-scope to machine-scope during service installation;
- cleared from user-scope after successful service install when promotion occurred.

Secrets must not be printed to the console, logs, Windows account descriptions, or UI.

## 4. Managed Local Accounts

When enabled by the customer, the agent may create and govern Cerberus-owned local Windows accounts. Managed accounts should:

- use a public, non-sensitive Windows description;
- keep internal ownership markers outside user-facing account fields;
- prevent the assigned user from changing the password;
- avoid password expiration for managed password rotation flows;
- be disabled before destructive deletion;
- be traceable to authorized control-plane commands.

## 5. Remote Desktop Readiness

Remote desktop access should be available only when the resource, assignment, user, workspace, local account, and service state all pass policy checks. Ambiguous state should not open access.

## 6. Network and Backend Interaction

The agent communicates with the configured backend and any configured private mesh endpoint. It should not call the public marketing site for operational commands, credentials, or telemetry.

## 7. Audit and Evidence

Operational commands, assignment changes, and critical state transitions should produce audit or evidence records in the control plane. Security and abuse signals should remain available to internal security surfaces without unnecessarily exposing implementation detail in customer operational history.

## 8. Uninstall, Unregister, and Deactivation

Uninstall removes the service and local machine state. Unregister attempts to notify the backend to deactivate the agent before local state is cleared. If the backend is unavailable, local cleanup may proceed and the control plane may later classify the agent as stale, unreachable, or inactive.

## 9. Security Review Checklist

Before production rollout, verify:

- signed binaries and trusted distribution;
- current legal consent gate;
- DPAPI secret storage and redaction;
- service install/start/stop/uninstall behavior;
- backend deactivation on unregister;
- managed local account create, rotate, disable, and delete;
- remote desktop authorization negative paths;
- stale and unreachable agent handling;
- audit evidence for critical operations.
