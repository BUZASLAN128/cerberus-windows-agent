# Third-Party Notices

Document version: `agent-third-party-notices-2026-06-02.v1`

This document records the current third-party boundary for the Cerberus Windows Agent. It is an engineering notice, not legal advice, and should be reviewed by counsel before public production distribution.

## Optional secure network connector

Cerberus can prepare an optional private mesh connectivity path for managed desktop operations. The current connector implementation uses Tailscale technical integration points when that feature is configured.

Cerberus does not bundle or redistribute the Tailscale Windows installer in this repository or in the Cerberus Agent release bundle. When the local repair/install action is used, the agent downloads the Windows MSI from the official Tailscale stable package host:

- `https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi`
- `https://pkgs.tailscale.com/stable/tailscale-setup-latest-x86.msi`
- `https://pkgs.tailscale.com/stable/tailscale-setup-latest-arm64.msi`

The download guardrails are:

- the default source must be HTTPS and under `pkgs.tailscale.com/stable/`;
- the file must be an MSI named like `tailscale-setup-*.msi`;
- a custom HTTPS MSI mirror is rejected unless `CERBERUS_TAILSCALE_ALLOW_CUSTOM_DOWNLOAD_URL` is explicitly enabled by the operator;
- the downloaded MSI must have a valid Authenticode signature;
- the signer subject must identify Tailscale before installation is started.

The customer-facing UI uses vendor-neutral labels such as `Secure network` and `Güvenli ağ`. Source code identifiers, operator configuration names, technical logs, and backend API names may still use `Tailscale` where precision is required for integration and troubleshooting.

Tailscale names and marks belong to Tailscale Inc. Cerberus should not imply Tailscale sponsorship, endorsement, or affiliation unless a separate written agreement allows it. Operators are responsible for complying with Tailscale's applicable license, terms, and trademark rules when enabling this optional connector.

## Verification snapshot

On 2026-06-02, the official `latest-amd64` MSI and the versioned `1.98.4-amd64` MSI were downloaded non-destructively from `https://pkgs.tailscale.com/stable/`. The versioned checksum matched its official `.sha256` sidecar, and both MSI files had a valid Authenticode signature with signer subject `Tailscale Inc.`. This is download and signature evidence only; it is not installer execution or service acceptance evidence.
