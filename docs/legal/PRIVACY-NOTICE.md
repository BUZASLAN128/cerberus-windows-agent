# Cerberus Windows Agent Privacy Notice

Document version: `agent-privacy-2026-05-23.v1`

This notice describes the data categories the Cerberus Windows Agent may process during installation, registration, service operation, support, and uninstall.

This document is a product/legal draft and should be reviewed by counsel before public production distribution.

## 1. Data Categories

Depending on configuration, the agent may process:

- device registration identifiers;
- tenant or workspace identifiers;
- device fingerprint and machine metadata needed to recognize the enrolled machine;
- agent version, build channel, build identifier, and capability status;
- service health, heartbeat time, and connectivity status;
- local managed account status, excluding passwords;
- command result status for authorized operations;
- remote desktop readiness status;
- update and repair status;
- error messages with secret redaction applied.

## 2. Data Not Intended for Normal Telemetry

Normal agent telemetry is not intended to collect:

- customer documents or source files;
- arbitrary filesystem listings;
- browser cookies or saved passwords;
- Windows account passwords;
- DPAPI secret payloads;
- private keys;
- OAuth access or refresh tokens;
- screenshots or session recordings unless a separately documented recording feature is enabled.

## 3. Purposes

The agent processes data to:

- enroll and identify a managed machine;
- verify service health;
- enforce workspace-scoped access;
- support remote desktop readiness;
- execute authorized operational commands;
- maintain audit and evidence records;
- support troubleshooting, repair, update, and uninstall.

## 4. Storage

Local agent credentials are stored using Windows DPAPI. User-scope registration can be promoted to machine-scope service credentials during service installation. The legal consent record is not a secret and is stored as a local JSON record so the installer can verify acceptance.

Backend retention and export behavior should be governed by the customer's Cerberus deployment agreement and environment policy.

## 5. Sharing

Agent data is sent to the configured Cerberus backend and related infrastructure required for the customer's deployment. The public website does not receive agent telemetry, local credentials, or machine details.

## 6. Customer Controls

Customers can control agent processing by:

- assigning or removing workspace access;
- disabling managed local accounts;
- revoking resource access;
- uninstalling the service;
- unregistering the device;
- deactivating stale or unreachable agents from the control plane.

## 7. Security Measures

The agent uses scoped credentials, request signing, DPAPI-backed local storage, secret redaction in logs, and fail-closed authorization expectations. Customers should run current signed builds and restrict local administrator rights.

## 8. Contact

Privacy requests should be routed to the organization that operates the Cerberus deployment or to the customer administrator responsible for the workspace.
