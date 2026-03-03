# Cerberus Windows Agent (v1)

Single executable, multiple modes:
- `--tray`: interactive onboarding (Casdoor OAuth) + stores secrets via DPAPI
- `--register`: non-GUI onboarding (SSO PKCE in browser) + stores secrets via DPAPI
- `--service`: background polling loop (heartbeat, command execution, result reporting)
- `--install-service`: install Windows Service (LocalSystem)
- `--uninstall-service`: uninstall Windows Service

Preflight/self-test:
- `--self-test`: runs offline + (if registered) online smoke checks; exits non-zero on failure.
- `scripts/preflight.ps1`: local gate before GitHub/live (build + test + publish + self-test).

Publish (portable, no .NET Desktop Runtime required):
```powershell
dotnet publish src/Cerberus.Agent.App/Cerberus.Agent.App.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true
```

Repo layout:
- `src/Cerberus.Agent.App`: WPF shell + CLI mode switching (MVP in progress)
- `src/Cerberus.Agent.Core`: contracts + interfaces for Core loop/modules
- `src/Cerberus.Agent.Security`: DPAPI secret store + RSA request signing
- `src/Cerberus.Agent.Observability`: sanitization utilities (Serilog wiring later)
- `src/Cerberus.Agent.Integrations.*`: integration modules (Tailscale/AD)
- `tests/`: xUnit tests (property tests later)

Build:
```powershell
dotnet build Cerberus.WindowsAgent.slnx -c Release
```
