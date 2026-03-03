# Contributing

## Branching Strategy

- Default working branch: `dev`
- Optional secondary integration branch: `develop`
- `main` is manual-promotion only
- Open PRs to `dev` unless explicitly requested otherwise

## Local Validation

Run before opening PR:

```powershell
dotnet build src/Cerberus.Agent.App/Cerberus.Agent.App.csproj -c Release
dotnet test tests/Cerberus.Agent.Core.Tests/Cerberus.Agent.Core.Tests.csproj -c Release
```

## CI/CD Rules

- `dev` / `develop`: CI + auto prerelease package
- `main`: manual workflow dispatch required for release

## Commit Guidance

- Keep commits focused and atomic
- Use conventional prefixes when possible:
  - `feat:`
  - `fix:`
  - `ci:`
  - `docs:`
  - `chore:`

## Security Expectations

- Never commit secrets, tokens, private keys, or production endpoints
- Preserve DPAPI encryption flow and request-signing behavior
- Redact sensitive values in logs and issue reports

