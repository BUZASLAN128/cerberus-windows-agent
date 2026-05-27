# Cerberus Windows Agent Bulgular V2

**Tarih**: 2026-05-26  
**Kapsam**: exe davranisi, MSI kurulumu, service/tray/setup ayrimi, updater/uninstaller, localization, release ergonomisi  
**Kaynaklar**: yerel Cerberus kodu, Tailscale, Fleet Orbit, RustDesk, PowerToys upstream snippet paketi, resmi vendor dokumanlari  

## Ozet

Agent mimarisi dogru yone donmus durumda: per-machine MSI, Program Files kurulumu, ayri service/tray/setup/updater/uninstall binary'leri ve EULA kapisi var. Eksik taraf daha cok urun davranisi ve isletim kalitesi: duplicate pencere/tray, desktop shortcut default'u, stale README, localization eksigi, enterprise MSI properties, update/uninstall acceptance ve reboot sonrasi gercek kanit.

## Release Checklist

| # | Bulgu | Durum | Owner file | Support test | Live evidence | Acceptance criteria |
|---|---|---|---|---|---|---|
| 1 | Duplicate setup/tray instance | Support kapandi, live gerekli | `src/Cerberus.Agent.App/ProcessInstanceGuard.cs`, `src/Cerberus.Agent.App/Program.cs`, `src/Cerberus.Agent.Tray/Program.cs` | `ProcessInstanceGuardTests` | MSI kurulu makinede setup'a 5 kez tiklama + reboot sonrasi tray kontrolu | Tek setup penceresi, tek tray icon/process |
| 2 | Desktop shortcut default'u eski yazilim hissi veriyor | Support kapandi, live gerekli | `src/Cerberus.Agent.Installer/Package.wxs` | `AgentLegalConsentTests` MSI static assertions | MSI default kurulum sonrasi desktop kontrolu | Default desktop shortcut yok; `CREATE_DESKTOP_SHORTCUT=1` ile var |
| 3 | Customer tray menusu fazla teknik | Support kapandi, live gerekli | `src/Cerberus.Agent.Tray/Program.cs` | Static/unit + manual smoke | Tray context menu screenshot | Normal menu: status/setup/diagnostics/repair/quit; service start/stop sadece repair altinda |
| 4 | Workspace/tenant dili agent UI'da eksik | Foundation kapandi, live/UI polish gerekli | `src/Cerberus.Agent.Tray/Program.cs`, `src/Cerberus.Agent.App/MainWindow.xaml.cs` | Localization/status render unitleri | Setup/tray screenshot | Raw `agent_id` musteri UI'da yok; workspace/account/status alanlari var |
| 5 | README ve release dokumani stale | Support kapandi | `README.md` | README string/static scan | Release operator dry-read | Per-machine split runtime, Program Files, Setup/Tray/Service/Updater/Uninstall dogru anlatilir |
| 6 | Update modeli imzali MSI uzerinden kapanmali | Support kapandi, live update gerekli | `src/Cerberus.Agent.Updater/Program.cs`, `src/Cerberus.Agent.App/Updates/*`, `scripts/build-public-release.ps1` | `AgentUpdateManifestValidatorTests`, `AgentUpdateStagerTests`, release build | Eski MSI -> yeni MSI live update | Signed/checksum/channel gecmeden update yok; service path/version dogrulanir |
| 7 | Uninstall ve portal lifecycle birlikte kapanmali | Support kapandi, live gerekli | `src/Cerberus.Agent.Uninstall/Program.cs`, backend lifecycle client | Unit/support + release build | Uninstall artifact + portal projection | Backend reachable ise self-deactivate; unreachable ise local uninstall devam eder ve portal TTL unavailable gosterir |
| 8 | AppData executable yasak, Program Files canonical | Support kapandi, install-tree live gerekli | `src/Cerberus.Agent.Installer/Package.wxs`, release script | MSI/static + release build | Program Files install tree screenshot/listing | Exe/DLL sadece Program Files; AppData sadece config/cache/log |
| 9 | Enterprise MSI properties eksik | Support kapandi, live gerekli | `src/Cerberus.Agent.Installer/Package.wxs`, `src/Cerberus.Agent.App/UiConfigStore.cs` | `AgentLegalConsentTests` MSI property scan | MSI property ile local smoke | Non-secret config HKLM'e yazilir; secret MSI property yok |
| 10 | Dil bariyeri cozumu eksik | Foundation kapandi, live/UI sweep gerekli | `src/Cerberus.Agent.App/Localization/*`, WiX `.wxl` | `AgentLocalizationTests` | TR/EN Windows veya `CERBERUS_LANGUAGE` smoke | TR/EN/fallback calisir; backend serbest UI metni tasimaz |
| 11 | Diagnostics/support bundle eksik | Support kapandi, live gerekli | `src/Cerberus.Agent.App/Diagnostics/AgentDiagnosticsBundle.cs`, tray menu | `AgentDiagnosticsBundleTests` | Tray `Export diagnostics` artifact | Zip/json redacted; token/private key/secret yok |
| 12 | Reboot acceptance release gate olmali | Acceptance acik | scripts + manual acceptance evidence | Support tests yeterli degil | 5x/10x gercek zincir tablosu | Release adayi musteri hazir denmeden once full zincir gecer |

**Kanıt seviyesi notu**: Bu dosyadaki unit/support testleri musteri hazir kabulü sayilmaz. Public Windows agent icin gercek kabul `MSI -> EULA -> PKCE -> register -> portal claim -> service start -> reboot -> update/uninstall` zincirinin 5x/10x kosulmasiyla kapanir.

## Guncel Support Kaniti

- **support/unit**: `dotnet test tests/Cerberus.Agent.Core.Tests/Cerberus.Agent.Core.Tests.csproj -c Release` -> 131 passed, 0 failed, 0 skipped.
- **support/build/package**: `$env:AGENT_RELEASE_ARTIFACT_BASE_URL='https://example.invalid/cerberus-agent'; pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/build-public-release.ps1 -Version 0.2.104-dev.local -Channel dev -SkipTests -AllowUnsignedDevBuild` -> split runtime publish + MSI build + checksum/SBOM/provenance/update-manifest/release-gate produced under `out/public-release/publish`.
- **artifact**: `out/public-release/publish/Cerberus.Agent.Setup-dev-0.2.104-dev.local.msi` produced as unsigned dev MSI. This is build evidence, not customer-ready release evidence.

## Upstream Karsilastirma Bulgulari

### 1. Duplicate setup/tray instance

- **Durum**: Patchlendi, support test gecti; live acceptance gerekli.
- **Kanıt**: Cerberus setup/tray icin single-instance guard eklendi. `ProcessInstanceGuardTests` support seviyesinde gecti.
- **Karsilastirma**: Tray tabanli agentlarda yeniden tiklama yeni pencere yigmaz; mevcut instance one gelir.
- **Kabul**: MSI kurulu makinede setup'a 5 kez tiklayinca tek pencere; reboot sonrasi tek tray icon/process.

### 2. Desktop shortcut default'u eski yazilim hissi veriyor

- **Durum**: Patchlendi; live MSI kurulum kaniti gerekli.
- **Kanıt**: `Package.wxs` desktop setup shortcut component'i artik `CREATE_DESKTOP_SHORTCUT = 1` kosuluna bagli. Default property `0`.
- **Karsilastirma**: AnyDesk desktop icon'u parametre ile kontrol ediyor; TeamViewer MSI desktop shortcut'i remove/property ile yonetiyor; Tailscale default olarak tray sinyali veriyor.
- **Karar**: Default desktop shortcut kapali. Start Menu ve tray default acik. Desktop shortcut sadece `CREATE_DESKTOP_SHORTCUT=1` MSI property veya UI checkbox ile acilsin.

### 3. Customer tray menusu fazla teknik

- **Durum**: Patchlendi; tray screenshot/live smoke gerekli.
- **Kanıt**: Tray normal menusu sade durum/setup/diagnostics/repair/quit modeline cekildi. `Start service` ve `Stop service` normal menuden cikti, repair altina alindi.
- **Karsilastirma**: Cloudflare WARP service/GUI ayrimini yapiyor; kullanici normalde service kontrolunu degil baglanti durumunu goruyor.
- **Karar**: Normal menu: workspace adi, status, setup/repair, diagnostics, quit. Service start/stop sadece `Advanced repair tools` altinda.

### 4. Workspace/tenant dili agent UI'da eksik

- **Durum**: Kismi patchlendi; workspace/account bilgisinin runtime kaynagi sonraki polish isi.
- **Sorun**: `Registered yes` veya agent id musteri icin anlamsiz.
- **Kanıt**: Raw `agent_id` musteri menusu/ana setup durumunda gosterilmez; tray status alanlari localization altyapisina baglandi.
- **Karar**: Setup/tray durum satiri `Workspace`, `Portal account`, `Service`, `Connector`, `Last heartbeat` olarak gosterilecek. Raw agent id sadece diagnostics export'ta kalacak.

### 5. README ve release dokumani stale

- **Durum**: Patchlendi; release operator review gerekli.
- **Kanıt**: README split runtime, Program Files, MSI EULA, portal claim ve MSI property modelini anlatacak sekilde guncellendi.
- **Karar**: README canonical mimariyi anlatmali: `Setup.exe`, `Tray.exe`, `Service.exe`, `Updater.exe`, `Uninstall.exe`, Program Files, MSI EULA, portal claim, reboot behavior.

### 6. Update modeli imzali MSI uzerinden kapanmali

- **Durum**: Kismen var, acceptance eksik.
- **Karsilastirma**: Fleet Orbit TUF tabanli target/channel modeli kullaniyor; Tailscale update tarafinda imza dogrulama katmani ayiriyor; PowerToys update state ve installer secimini ayrica belgeliyor.
- **Karar**: V1 canonical update artifact `MSI`. Service sadece imza/checksum/channel dogrular ve updater'i cagirir. Updater service/tray kapatir, MSI uygular, service path/version dogrular.
- **Kabul**: Eski MSI -> yeni MSI update 5x live acceptance.

### 7. Uninstall ve portal lifecycle birlikte kapanmali

- **Durum**: Kismen var, live acceptance eksik.
- **Karar**: Uninstaller best-effort self-deactivate gonderir, portal unreachable ise local uninstall devam eder. Portal tarafinda heartbeat TTL agent'i unavailable/deactivated gosterir. UI "tekrar baglan" ve "kaydi kaldir" ayrimini net verir.

### 8. AppData executable yasak, Program Files canonical

- **Durum**: Yeni MSI dogru yonde.
- **Karsilastirma**: Tailscale `C:\Program Files\Tailscale`, AnyDesk `C:\Program Files (x86)\AnyDesk`, Cloudflare WARP Program Files + ProgramData modelini izliyor.
- **Karar**: Exe/DLL sadece Program Files altinda. AppData sadece kullanici config/cache/log gibi executable olmayan state icin. ProgramData machine logs/update staging icin kullanilabilir.

### 9. Enterprise MSI properties eksik

- **Durum**: Patchlendi; property ile local smoke gerekli.
- **Karsilastirma**: Tailscale MSI properties'i policy registry'ye yazar; TeamViewer CUSTOMCONFIGID/assignment iki adimli deploy sunar; AnyDesk install path/start-with-win/shortcut/update parametreleri sunar.
- **Karar**: Public properties:
  - `CERBERUS_BACKEND_URL`
  - `CERBERUS_SSO_BASE_URL`
  - `CERBERUS_SSO_CLIENT_ID`
  - `CERBERUS_CHANNEL`
  - `CERBERUS_LANGUAGE`
  - `CREATE_DESKTOP_SHORTCUT`
  - `START_TRAY_ON_LOGIN`
  - `CERBERUS_EULA_ACCEPTED` sadece approved managed/headless deployment.

### 10. Dil bariyeri cozumu eksik

- **Durum**: Foundation patchlendi; TR/EN live UI sweep gerekli.
- **Karsilastirma**: RustDesk app stringleri TR dahil dil dosyalarinda tutuyor; WiX installer stringleri `.wxl` ile localize ediyor; PowerToys C#/UI tarafinda resx ve satellite resource DLL modelini belgeliyor.
- **Karar**:
  - .NET UI icin `Resources.resx`, `Resources.tr-TR.resx`, `Resources.en-US.resx`.
  - WiX icin `Package.en-us.wxl` ve `Package.tr-tr.wxl`.
  - Tek `AgentLocalizer` servisi Setup/Tray/Uninstall tarafinda kullanilir.
  - Dil secim sirası: `CERBERUS_LANGUAGE` MSI property -> kullanici ayari -> portal preferred locale -> Windows UI culture -> `en-US`.
  - Backend key/value text gondermez; sadece `preferred_locale` veya hata kodu gonderir.
- **Kabul**: TR Windows'ta Turkce UI, EN Windows'ta Ingilizce UI, gecersiz culture'da `en-US` fallback.

### 11. Diagnostics/support bundle eksik

- **Durum**: Patchlendi; tray uzerinden live export kaniti gerekli.
- **Karar**: Tray icinde "Export diagnostics" olacak. Cikti redacted zip/json: version, install root, service status, last heartbeat, update state, sanitized logs. Token/secret/private key yok.

### 12. Reboot acceptance release gate olmali

- **Durum**: Acceptance acik; support/build kaniti var, real Windows 5x/10x kaniti yok.
- **Karar**: Release gate su zinciri kosmadan "customer ready" demeyecek:
  1. MSI install
  2. EULA kabul
  3. Setup auto open
  4. PKCE/register
  5. Portal claim
  6. Service install/start
  7. Reboot
  8. Tek tray icon/process
  9. Setup'a tekrar tiklayinca tek pencere
  10. Uninstall ve portal state dogrulama

## Mimari Kararlar

- **Canonical runtime**: `Cerberus.Agent.Service.exe` boot process, `Cerberus.Agent.Tray.exe` user login UI, `Cerberus.Agent.Setup.exe` onboarding, `Cerberus.Agent.Updater.exe` MSI update, `Cerberus.Agent.Uninstall.exe` customer uninstall.
- **Customer flow**: CLI yok; MSI ve UI var. CLI sadece support/admin/debug.
- **Security posture**: Service claim'den once baslamaz. EULA gizli kabul edilmez. Update signed/checksum/channel dogrulamadan uygulanmaz.
- **Install root**: Program Files. User data AppData; machine logs/update staging ProgramData.
- **UI posture**: Normal UI musteri diliyle; internal id/exception/token yok. Advanced repair kapali bolumde.

## Uygulama Prompt / Hook

Detayli tekrar kullanilabilir prompt: `docs/research/windows-agent-yardimci-kaynaklar/agent-modernization-hook-prompt.md`.

## Test ve Kabul Plani

- **Support**: `dotnet build` App/Tray/Service/Updater/Uninstall/MSI; single-instance unit; localization fallback unit. Son kosum: 131/131 support/unit pass ve unsigned dev MSI artifact uretildi.
- **Live 1x smoke**: MSI install + setup + claim + service + tray.
- **Acceptance 5x**: full install/reboot/update/uninstall zinciri.
- **Final 10x**: release adayi icin ayni zincir, ayni ortam siniri uzerinden.

## Kalan Riskler

- Live Windows acceptance kosulmadan agent "customer-ready" sayilmaz.
- TR/EN localization foundation var, fakat gercek Windows UI culture + MSI property smoke henuz kosulmadi.
- Update/uninstall lifecycle icin support/build kaniti var; eski MSI -> yeni MSI update ve portal lifecycle live kaniti henuz yok.
- Reboot sonrasi tek tray icon/process ve setup shortcut'a 5 kez tiklama live kaniti henuz yok.
