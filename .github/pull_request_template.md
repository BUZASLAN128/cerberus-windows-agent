## Summary

- What changed?
- Why was it needed?

## Validation

- [ ] `dotnet build src/Cerberus.Agent.App/Cerberus.Agent.App.csproj -c Release`
- [ ] `dotnet test tests/Cerberus.Agent.Core.Tests/Cerberus.Agent.Core.Tests.csproj -c Release`
- [ ] Release workflow impact checked (`.github/workflows/auto-publish-exe.yml`)

## Security Checklist

- [ ] No secrets/tokens/keys committed
- [ ] DPAPI/crypto/signing flow not weakened
- [ ] Logs/errors sanitize sensitive values

## Branching Policy

- Target branch is `dev` (default).
- `main` merges are manual promotions only.

