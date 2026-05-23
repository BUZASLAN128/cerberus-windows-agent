# Cerberus Windows Agent End User License Agreement

Document version: `agent-eula-2026-05-23.v1`

This End User License Agreement governs installation and use of the Cerberus Windows Agent. The agent must not be installed, registered, or run as a Windows service unless the current legal package has been accepted.

This document is a product/legal draft and should be reviewed by counsel before public production distribution.

## 1. Product Scope

The Cerberus Windows Agent connects a customer-owned Windows machine to a Cerberus-controlled desktop operations control plane. Depending on enabled features, the agent may:

- register the device to an authorized workspace;
- run as a Windows service;
- report operational health, version, capability, and connectivity status;
- receive authorized commands from the control plane;
- prepare remote desktop access paths;
- manage Cerberus-owned local Windows accounts for assigned users;
- support install, repair, update, disable, unregister, and uninstall workflows.

The agent is not a general-purpose remote control tool. It is intended for governed desktop operations with identity, authorization, audit, and revocation controls.

## 2. Acceptance

By selecting an acceptance control, running the agent with `--accept-eula`, or allowing an administrator to install the service after acceptance, the customer confirms that:

- the installer is being run by an authorized person;
- the machine may be enrolled into the configured Cerberus workspace;
- the organization accepts the EULA, Privacy Notice, and Security Disclosure versions listed in the consent record;
- the organization is responsible for ensuring that use of the agent is permitted under its internal policies and applicable law.

If the legal package is not accepted, installation, registration, and service install must stop.

## 3. Authorized Use

The agent may only be used for legitimate internal operations, support, administration, testing, or approved customer workflows. The customer must not use the agent to:

- access systems without authorization;
- bypass identity, authorization, audit, or revocation controls;
- hide or tamper with audit records;
- distribute modified binaries as official Cerberus builds unless separately authorized;
- reverse engineer, bypass, or disable security controls except where applicable law expressly permits.

## 4. Customer Responsibilities

The customer is responsible for:

- installing the agent only on machines it owns or is authorized to manage;
- selecting authorized workspace administrators and operators;
- protecting administrator credentials and SSO accounts;
- reviewing assignments, local account lifecycle, and remote session access;
- removing the agent from machines that should no longer be managed;
- complying with employment, privacy, monitoring, and data protection obligations.

## 5. Local System Changes

The agent may make local changes required for governed desktop operations, including:

- installing or removing a Windows service;
- storing agent credentials through Windows DPAPI;
- writing operational state under the Cerberus Agent application data directories;
- creating, disabling, rotating, or deleting Cerberus-managed local Windows accounts when commanded by the authorized control plane;
- applying local account flags required for managed account safety, such as preventing password changes and password expiration;
- preparing remote desktop group membership for authorized managed accounts;
- exporting or applying private mesh connectivity commands when the workspace is configured for that feature.

The agent should not write internal assignment identifiers, tokens, or control-plane metadata into Windows user-facing account descriptions.

## 6. Updates and Repair

Cerberus may provide updates, repair packages, or replacement binaries. Updates may change functionality, improve security, or modify operational behavior. Production distribution should use signed binaries and a documented update channel.

## 7. Data and Telemetry

The agent may send operational data needed to run the service. Data handling is described in `PRIVACY-NOTICE.md`. The agent must not intentionally transmit customer documents, screenshots, passwords, private keys, or arbitrary file contents as part of normal health telemetry.

## 8. Security

The agent is designed to fail closed when identity, authorization, registration, or command state is ambiguous. Security behavior is described in `SECURITY-DISCLOSURE.md`.

## 9. Termination and Uninstall

The customer may uninstall the service or unregister the device through supported commands or installer flows. Unregistering may notify the control plane that the agent should be deactivated. If the backend cannot be reached, local cleanup may still proceed and the control plane may later mark the agent unreachable or inactive.

## 10. Warranty and Liability

Unless a separate written agreement says otherwise, the agent is provided for evaluation and controlled rollout without a broad uptime, fitness, or uninterrupted-operation warranty. Liability, support scope, and service levels should be governed by the applicable order form, master agreement, or production contract.

## 11. Contact

Operational and security contact details should be provided by the Cerberus operator or customer administrator responsible for the deployment.
