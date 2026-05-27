# Windows Agent Yardimci Kaynaklar

Bu klasor Cerberus Windows Agent icin kucuk upstream referans paketidir. Buradaki dosyalar calisan Cerberus koduna bagli degildir; sadece installer, updater, tray, service ve localization kararlarini incelerken hizli karsilastirma yapmak icindir.

## Kapsam

- `upstream-snippets/tailscale`: Windows service install, update imzasi, systray/autostart referanslari.
- `upstream-snippets/fleet`: Fleet Orbit packaging, TUF update ve Windows desktop/service referanslari.
- `upstream-snippets/rustdesk`: WiX MSI, upgrade, tray, updater ve TR/EN localization referanslari.
- `upstream-snippets/PowerToys`: WiX installer, update process, tray/autostart ve resx localization referanslari.

## Kullanim Kurali

- Bu dosyalardan dogrudan kod kopyalanmaz.
- Karar alinacaksa once `docs/phase7/bulgular-v2.md` icindeki bulgu ve kabul kriterlerine baglanir.
- Her upstream repo lisans dosyasi ilgili alt klasorde tutulur.
- Bu paket vendor dependency degildir; release artifact veya build input olarak kullanilmaz.

## Resmi Dokuman Referanslari

- Tailscale Windows MSI: https://tailscale.com/docs/install/windows/msi
- Cloudflare WARP Windows client: https://developers.cloudflare.com/warp-client/get-started/windows/
- Cloudflare managed deployment: https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/mdm-deployment/
- TeamViewer MSI deployment: https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-tensor-classic/deployment/deploy-teamviewer-host-or-full-client-9-9/
- AnyDesk Windows CLI/MSI: https://support.anydesk.com/v1/docs/command-line-interface-for-windows

