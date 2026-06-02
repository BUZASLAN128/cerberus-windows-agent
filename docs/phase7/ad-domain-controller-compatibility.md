# AD and Domain Controller Compatibility

Date: 2026-06-02

This note records the current Cerberus Windows Agent boundary for Active Directory and Windows local account commands.

## Current behavior

- `windows.local_user.create`, `windows.local_user.disable`, and `windows.local_user.delete` are local SAM account commands.
- On Windows domain controllers, local SAM account mutation is not supported. The agent checks `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType`; `LanmanNT` is treated as a domain controller.
- When the machine is a domain controller, local user commands fail closed with `FAILED` and post-verify code `local_accounts_unsupported_on_domain_controller`.
- `ad.user.create`, `ad.user.update`, and `ad.user.disable` are wired through the AD provider boundary, but real AD mutation executors are intentionally not implemented in this foundation build.
- A domain-joined machine currently returns `not_implemented` for AD mutation commands; a non-domain-joined machine returns `not_domain_joined`.

## Acceptance gap

Unit tests cover command parsing, local-user fail-closed guards, and domain-controller product type mapping. They do not prove real Active Directory behavior.

Before closing AD/DC readiness for production, run a live matrix on controlled Windows hosts:

- workstation not domain-joined;
- member server or workstation domain-joined;
- domain controller.

For each host, capture command result persistence, local user state, AD state, portal status, and cleanup evidence. Do not treat mock handlers or registry-only unit tests as public-agent acceptance.
