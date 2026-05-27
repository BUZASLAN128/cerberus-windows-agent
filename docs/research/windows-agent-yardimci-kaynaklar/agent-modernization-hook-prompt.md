# Cerberus Windows Agent Modernization Hook Prompt

Bu prompt, Windows Agent uzerinde exe davranisi, installer mimarisi, runtime parcalari, update/uninstall ve localization isleri acilirken kullanilacak kalite hook'udur.

```text
Classification: coding
Skill Used: coder-agent

Objective:
Cerberus Windows Agent'i modern enterprise Windows agent davranisina yaklastir. Degisiklikler musteri akisini basitlestirmeli, servis/tray/setup/updater/uninstall ayrimini korumali, Program Files per-machine kurulumunu canonical tutmali, AppData icinde executable barindirmamali, tek-instance davranisini garanti etmeli, dil bariyerini TR/EN kaynak sistemiyle cozmelidir.

Scope:
- cerberus-windows-agent MSI, setup, tray, service, updater, uninstall, release scriptleri ve agent docs.
- Backend protokol, DPAPI credential format, service install/start/stop/uninstall davranisi, heartbeat/command protokolu veya managed local user davranisi degisirse once scoped AGENTS ask-first kurallarini uygula.
- Upstream referanslar yalnizca docs/research/windows-agent-yardimci-kaynaklar altinda inceleme kanitidir; dogrudan kaynak kopyalama yapma.

Non-goals:
- Commodity remote desktop clone davranisi ekleme.
- Customer path icin CLI zorunlulugu.
- Gizli EULA kabul ettirme.
- AppData'ya executable kurma.
- Unsafely silent update, unsigned update veya in-process binary overwrite.

Required decisions:
- Customer default: MSI -> EULA -> install -> setup UI -> PKCE/register -> portal claim -> service install/start -> tray ready.
- Desktop shortcut default off; Start Menu + tray default on.
- Setup ve tray single-instance; yeniden tiklama mevcut pencereyi one alir veya tray menu acilir.
- Service boot'ta, tray user login'de calisir.
- Language resolution: MSI property/user setting/portal locale/Windows UI culture/en-US fallback.
- UI strings hardcoded degil, resx kaynaklarindan gelir; WiX textleri wxl kaynaklarindan gelir.

Acceptance criteria:
- Build: App, Tray, Service, Updater, Uninstall, MSI Release build 0 warning.
- Support tests: single-instance, localization fallback, installer property parse, updater manifest validation.
- Live 5x: MSI install, EULA, setup, PKCE/register, portal claim, service start, reboot, exactly one tray icon/process, repeated setup click opens one window, uninstall.
- Evidence quality labels: unit/support/live/acceptance ayri raporlanir; mock-only sonuc customer-ready sayilmaz.
- No secrets, tokens, private keys, local auth state, generated credentials committed.
```

