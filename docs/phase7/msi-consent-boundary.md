# MSI consent boundary

The installer records machine-level legal consent only for a fresh install with
`CERBERUS_EXPLICIT_CONSENT=1`. The full UI sets that property only when the
license-dialog acceptance is selected. An authorized silent install must pass
both `CERBERUS_EULA_ACCEPTED=1` and `CERBERUS_EXPLICIT_CONSENT=1` only after
explicit acceptance. The second property is intentionally distinct: the
existing updater passes the first property automatically. An upgrade or repair
does not create a new versioned acceptance marker, even when a flag is present.

Machine MSI consent is read from the 64-bit HKLM registry only after checking
the owner and write permissions of every key in its path. It also requires the
`explicit-v1` marker and current product, document versions and `msi_explicit`
source. Missing, stale, legacy unmarked, unreadable or untrusted records do
not grant consent. Existing protected machine JSON and user-scoped acceptance
remain supported; MSI machine consent does not become a user's own consent.
Where no current trusted acceptance survives an upgrade, obtain an explicit
current acceptance through a supported user/CLI path before relying on it.

Local tests cover marker/version checks, untrusted registry ACLs and parent
chains, user-consent compatibility, and installer source conditions. Local
WiX schema compilation and read-only MSI table inspection are support evidence
only: ICE validation could not access Windows Installer in the sandbox, and no
MSI installation, UI, repair, major upgrade, rollback or uninstall was run.
Those real paths remain required before rollout. Do not treat test fixture MSI
outputs as installable packages.

The local Wix build reused intermediate results when switched from Server to
Desktop with the same intermediate directory. Use a distinct
`BaseIntermediateOutputPath` for each profile in verification and check the
resulting MSI component identity; the source build cache issue is not fixed here.
