# CERBERUS WINDOWS AGENT - PHASE 7F BULGULAR VE KOD DENETİMİ

**Tarih**: 2026-05-22  
**Kapsam**: Production runtime, security, data integrity, test quality  
**Format**: Sorun → Neden → Sonuç → Dosya Yolu  

---

## 🔴 KRİTİK BULGULAR (P0)

**1.** Revoke + Clear Credentials → Backend response ile agent kalıcı kill edilebilir, confirmation yok → Confirmation doğrulaması başarısızsa credential temizleme yapılmıyor ve heartbeat döngüsü artık durdurulmuyor; yalnızca doğrulanmış `clear_local_credentials_confirmation` ile local credential clear sonrası `Stop` dönülüyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\HeartbeatResponseHandler.cs:33-49` ✅ **FIXED**

**2.** Offline Buffer File Corruption → Crash durumunda file corrupt, partial write riski, atomic write yok → Telemetry verileri diske doğrudan yazılıyordu. Artık temp dosyasına yazılıp atomic move işlemi yapılıyor ve bozuk dosyalar karantinaya alınıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\OfflineTelemetryBuffer.cs:107-114` ✅ **FIXED**

**3.** Command Execution Exception → DispatchAsync exception fırlatırsa loop catch'e düşer, diğer commands çalışmaz → `CommandDispatcher` komut handler exception'larını `FAILED` sonucuna çeviriyor; heartbeat loop sonraki komutu işlemeye devam ediyor ve testte exception alan komut ile başarılı komut sonucu birlikte submit ediliyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\CommandDispatcher.cs` ✅ **FIXED**

**4.** Service Credential Promotion → User-scope credentials machine-scope'a kopyalanıyor, cryptographic verification yok → Promotion sonrası destination store'dan tüm credential payload tekrar okunuyor; identity, refresh token, private key, backend URL ve Tailscale alanları birebir karşılaştırılıyor ve SHA-256 canonical fingerprint uyuşmazsa fail-closed hata veriliyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Actions\AgentServiceProvisioning.cs` ✅ **FIXED**

**43.** DPAPI Secret Store File ACL Race Condition → `DpapiSecretStore.cs` dosyasında secrets dosyası diske yazılırken (`WriteAllBytesAsync`) varsayılan miras alınan izinlerle oluşturulur; kısıtlayıcı ACL izinleri (`LockDownAcl`) ancak dosya yazıldıktan sonra uygulanır → Secret dosyası artık `FileShare.None` ve `WriteThrough` ile açılıyor, içerik yazılmadan önce ACL kilitleniyor, ardından şifreli payload yazılıp flush ediliyor; içerik varsayılan ACL penceresinde diske düşmüyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Security\DpapiSecretStore.cs` ✅ **FIXED**

---

## ⚠️ YÜKSEK RİSK (P1)

**5.** Offline Buffer Pruning → Buffer limit aşınca kritik events önce atılıyordu (event priority=5, snapshot priority=10) → Event önceliği snapshot üstüne taşındı, batch okuma priority descending çalışıyor ve düşük öncelikli eski kayıtlar önce budanıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\OfflineTelemetryBuffer.cs` ✅ **FIXED**

**6.** Snapshot Timing Race → nextSnapshotAt local state restart sonrası ilk heartbeat'te snapshot flood yapıyordu → Heartbeat loop artık initial snapshot delay kullanıyor; testlerde gerektiğinde sıfırlanabiliyor, servis restart default akışı hemen snapshot basmıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\HeartbeatLoop.cs` ✅ **FIXED**

**7.** Command Execution Blocking → Commands sıralı çalışıyor, uzun command diğerlerini blokluyordu → Pending command dispatch artık sınırlı paralellik (`commandConcurrency`, default 2, max 8) ile çalışıyor; tek uzun komut batch'i tamamen kilitlemiyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\HeartbeatLoop.cs` ✅ **FIXED**

**8.** Update Handling Failure → Update failure sessizce ignore ediliyordu → Update exception'ları loglanıyor, `agent.update.failed` telemetry event'i backend'e gönderiliyor ve testle doğrulanıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\HeartbeatResponseHandler.cs`, `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\ServiceMode.cs` ✅ **FIXED**

**9.** Telemetry Buffer Disk I/O → Her enqueue/dequeue'da full file read/write vardı → Buffer instance başına memory cache eklendi; her işlem artık dosyayı tekrar tekrar okumuyor, mutasyonlar atomic write ile diske kalıcı yazılıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\OfflineTelemetryBuffer.cs` ✅ **FIXED**

**10.** Password Encryption Key Rotation → Public key payload'dan geliyor, key doğrulama zayıftı → Credential public key artık RSA >=2048, zorunlu SHA-256 fingerprint ve fingerprint mismatch kontrolünden geçmeden kullanılmıyor; stale/yanlış key fail-closed reddediliyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs` ✅ **FIXED**

**11.** Bootstrap Descriptor Revocation (CRITICAL SECURITY VULNERABILITY FOUND) → Legacy descriptor client imza alanını kriptografik doğrulamıyordu → Descriptor/enroll normal flow'dan kaldırıldı; source scan'de `BootstrapDescriptor`/`bootstrap/descriptor` route client kalmadı, registrar testleri payload'da `bootstrap_descriptor` olmadığını doğruluyor → `f:\cerberus-repos\cerberus-windows-agent\tests\Cerberus.Agent.Core.Tests\AgentRegistrarTests.cs` ✅ **FIXED**

**12.** Update Manifest Download → 200MB artifact download progress yok, timeout 30 saniye çok kısaydı → Update indirme artık ayrı HttpClient timeout'u kullanıyor (default 10 dk, env override), download progress loglanıyor ve testle doğrulanıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\ServiceMode.cs`, `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\AgentUpdateStager.cs` ✅ **FIXED**

**13.** Telemetry Section Exception → Section collector exception'ı snapshot'ı kırabilir, partial snapshot riski → Hatalar yakalanmıyordu. Artık `TelemetrySectionCapture` her bir toplayıcının hatasını `try-catch` ile izole ediyor ve hata durumunu snapshot verisinde failed olarak işaretliyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\Telemetry\TelemetrySectionCapture.cs` ✅ **FIXED**

**16.** Password Generation Weak → Base64 + "aA1!" pattern, predictable, brute force riski → Sabit pattern kullanılıyordu. Artık `RandomNumberGenerator` ile kriptografik olarak güvenli, karmaşık ve rastgele şifreler üretiliyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs:240-241` ✅ **FIXED**

**17.** Local User Rate Limiting → Command handler'lar rate limiting yoktu, aynı kullanıcı için back-to-back mutation spam mümkündü → Aynı username+mutation için kısa cooldown eklendi; duplicate mutation `local_user_rate_limited` ile fail-closed dönüyor, farklı mutation akışları gereksiz bloklanmıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs` ✅ **FIXED**

**18.** Local User Description → Description field validation yok, length limit yok (Windows: 256 karakter) → Windows SAM veritabanı limitleri kontrol edilmiyordu. Artık açıklama alanı maksimum 256 karakter olacak şekilde kırpılıyor ve doğrulanıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs:244-247` ✅ **FIXED**

**19.** Local User SID Exception → SID retrieval failure sessizce `null` dönüyordu → SID lookup artık status ile dönüyor; success metadata `local_sid_status` içine `ok`, `missing` veya exception türünü yazıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs` ✅ **FIXED**

**20.** Username Validation Regex → Pattern dokümantasyonu yoktu ve validasyon niyeti belirsizdi → Windows-safe kontrol ile Cerberus managed username shape ayrımı korunarak canonical pattern dokümante edildi; test sadece mevcut managed shape'i kabul ediyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs` ✅ **FIXED**

**21.** Password Key Validation → Public key validation yok, key size validation yok (min 2048 bit) → Gelen anahtarlar doğrudan kabul ediliyordu. Artık PEM formatı kontrol ediliyor, anahtar boyutu doğrulanıyor (>=2048 bit) ve SHA256 parmak izi (fingerprint) doğrulaması yapılıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs:267-275` ✅ **FIXED**

**22.** Update Rollback Plan → Update staging başarılı olursa sadece log yazılıyordu, eski staged sürümler temizlenmiyordu → Apply path mevcut binary'yi önce rename ile backup alıyor ve checksum/apply hatasında geri taşıyor; staging tamamlanınca eski staged sürümler budanıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\AgentUpdateStager.cs` ✅ **FIXED**

**23.** Update Apply Validation → planPath/file/elevation doğrulaması eksikti → Apply mode admin elevation şartı koyuyor; stager plan/artifact path'i trusted staging root altında doğruluyor, target allowlist ve checksum kontrolü yapıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Updates\UpdateApplyMode.cs`, `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\AgentUpdateStager.cs` ✅ **FIXED**

**24.** Telemetry Section Error → Section capture exception durumunda tüm snapshot fail olur, partial snapshot support yok → Hatalar yakalanmıyordu. (Bulgu 13 ile aynı) Artık yakalanıp partial snapshot destekleniyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Telemetry\WindowsTelemetryCollector.cs:27-38` ✅ **FIXED**

**25.** Telemetry Section Catalog → Hardcoded section catalog, feature flag support yoktu → `CERBERUS_AGENT_TELEMETRY_SECTIONS` allowlist eklendi; yalnız bilinen section isimleri seçiliyor, boş/yanlış config default güvenli catalog'a düşüyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Telemetry\Sections\WindowsTelemetrySectionCatalog.cs` ✅ **FIXED**

**27.** RSA Key Persistence → `RsaKeyManager` tek başına persistence yapmıyor diye işaretlenmişti → Runtime registration path `AgentRegistrar` anahtarı üretip private key'i `ISecretStore`/DPAPI üzerinden kalıcı kaydediyor; `RsaKeyManager` artık runtime owner değil, bulgu stale kabul edildi → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\AgentRegistrar.cs` ✅ **FIXED**

**29.** Log Sanitizer Performance → Her log entry için tüm regex'ler koşuyordu → `MayContainSecret` fast-path eklendi; secret sinyali yoksa regex/JSON parse maliyeti oluşmuyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Observability\Sanitizer.cs` ✅ **FIXED**

**30.** Log Sanitizer Coverage → Pattern-based redaction only, structured data redaction yoktu → JSON object/array parse + sensitive field-name redaction eklendi; nested `password`, `access_token`, `client_secret`, `refresh_token` gibi alanlar değer bağımsız maskeleniyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Observability\Sanitizer.cs` ✅ **FIXED**

**31.** File Logger Rotation → Log rotation yok, file size limit yok, retention policy yoktu → Agent logger artık boyut bazlı rotate ediyor, retention limiti uyguluyor ve eski logları temizliyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Observability\AgentFileLogger.cs` ✅ **FIXED**

**33.** Tailscale Auto Execution → Command file oluşturuluyor ama otomatik execute edilmiyordu → Handler artık Tailscale kurulu ama bağlı değilse machine-scope authkey ile `tailscale up` runner'ını çağırıyor, sonra probe sonucu connected olursa DONE dönüyor; debug `.cmd` export sadece auto-connect kapatılırsa fallback olarak kalıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleEnsureConnectedHandler.cs` ✅ **FIXED**

**34.** Tailscale Status Caching → Her probe'da external process spawn ediliyordu → Status probe 5 saniyelik process-result cache kullanıyor; kısa aralıklı heartbeat/telemetry çağrıları tekrar process spawn etmiyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleStatusProbe.cs` ✅ **FIXED**

**35.** Tailscale Command Security → Plain text auth key `.cmd` dosyasına yazılıyordu → Generated command artık authkey değerini diske yazmıyor; runtime `%CERBERUS_TAILSCALE_AUTHKEY%` env var yoksa fail ediyor ve testte key'in dosyaya düşmediği doğrulanıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleUpCommand.cs` ✅ **FIXED**

**36.** Tailscale ACL Lockdown → ACL olsa bile `.cmd` açık metin authkey içeriyordu → Authkey artık command/metadata içine yazılmıyor; local admin plaintext key okuyamaz, handler metadata `contains_plaintext_authkey=false` döndürüyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleEnsureConnectedHandler.cs` ✅ **FIXED**

**38.** Test Coverage Incomplete → Kritik güvenlik yollarında eksik unit coverage vardı → Revoke confirmation, credential promotion verification, telemetry redaction/allowlist, local user rate limit/key fingerprint, update staging/progress/cleanup ve Tailscale auto-connect yollarına focused unit/support testleri eklendi; gerçek OS E2E hâlâ acceptance riskidir → `f:\cerberus-repos\cerberus-windows-agent\tests\Cerberus.Agent.Core.Tests\*` ✅ **FIXED / SUPPORT EVIDENCE**

**41.** Test Assertions Limited → Basic assertion ağırlığı vardı → Yeni testler sadece status değil, payload içeriği, secret sızıntısı olmaması, progress log, cache/allowlist, command path/metadata ve retry attempt count gibi yan etkileri de doğruluyor → `f:\cerberus-repos\cerberus-windows-agent\tests\Cerberus.Agent.Core.Tests\*` ✅ **FIXED**

**42.** Test Infrastructure Mock → Bazı yollar static/reflection ağırlıklıydı → Tailscale handler'a injectable runner/probe/secret store path'i eklendi; update stager logger injection ve telemetry section allowlist testleriyle kritik side-effect yolları deterministic hale getirildi → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleEnsureConnectedHandler.cs`, `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\AgentUpdateStager.cs` ✅ **FIXED**

**44.** No Auto-Update Execution → `AgentUpdateCoordinator` yeni güncellemeyi indirip stage ediyor ancak servis süreç yönetimini kapatıp apply helper'ı başlatmıyor → Apply güvenliği, timeout, progress, backup/rollback ve cleanup düzeltildi; otomatik servis restart/apply davranışı service lifecycle değişikliği olduğu için ayrı product/acceptance kararı gerektirir → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Updates\AgentUpdateCoordinator.cs` ⚠️ **BLOCKED / SERVICE LIFECYCLE DECISION**

**45.** Retry Helper Spam on Client Errors → Tüm HTTP istemci hataları transient sayılıyordu → Retry helper artık yalnız status code olmayan transport hataları, timeout/cancel ve 5xx gateway/server outage durumlarını retry ediyor; 429 ve 4xx auth/client hataları tekrar denenmiyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\RetryHelper.cs` ✅ **FIXED**

**46.** Windows File Lock on Active Binary Update → Aktif binary üzerine overwrite copy deneniyordu → Apply path önce mevcut hedefi benzersiz backup adına rename ediyor, yeni artifact'i kopyalıyor, checksum doğruluyor ve hata halinde backup'ı geri taşıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\AgentUpdateStager.cs` ✅ **FIXED**

**47.** Tailscale Command File ACL Race Condition → `.cmd`/`.json` dosyaları ACL kilidinden önce plaintext authkey içeriyordu → Command file artık plaintext authkey içermiyor; ACL race hassas secret sızıntısı olmaktan çıktı ve dosya içeriği testle doğrulanıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleEnsureConnectedHandler.cs` ✅ **FIXED**

---

## ⚠️ ORTA RİSK (P2)

**14.** Network Telemetry IP Leak → Private IP adresleri backend'e ham gönderiliyordu → Network telemetry artık ham IP yerine `{family, scope, value}` redaction objesi gönderiyor; private/loopback/link-local adresler `private-ipv4/private-ipv6` olarak maskeleniyor ve testle doğrulanıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Telemetry\Sections\NetworkTelemetrySectionCollector.cs` ✅ **FIXED**

**15.** Service Uninstall Credential → Machine secrets user'a sync edilemiyor, silent failure riski vardı → Uninstall öncesi machine registration user-scope store'a verified promotion ile korunuyor; ancak farklı admin hesabından uninstall edilen gerçek Windows oturumunda “orijinal kullanıcı profiline yazma” live acceptance gerektirir → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Actions\AgentServiceProvisioning.cs` ⚠️ **PARTIAL / LIVE ACCEPTANCE REQUIRED**

**26.** Telemetry Context Immutable → LastHeartbeat nullable uyarısı not edilmişti → Mevcut context nullable contract açık (`HeartbeatResponse? LastHeartbeat`), collector path'lerinde null-safe erişim korunuyor; derleme/test uyarı üretmiyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Telemetry\WindowsTelemetryContext.cs` ✅ **FIXED**

**28.** Secret Store Scope → Sadece 2 DPAPI scope olduğu not edilmişti → Agent runtime modeli tek tenant/agent identity per installation kabul ediyor; tenant ayrımı local secret scope ile değil registered identity + backend authz ile yapılıyor. Daha granular local vault tasarımı protokol/credential-storage değişikliği sayılır ve V1 agent scope dışıdır → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Security\SecretStoreScope.cs` ✅ **FIXED / DESIGN CLARIFIED**

**32.** File Logger Concurrent → Single `_gate` lock console çıktısını da blokluyordu → Console write dosya rotate/write kilidinin dışına alındı; lock artık sadece file writer ve rotation bütünlüğünü koruyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Observability\AgentFileLogger.cs` ✅ **FIXED**

**37.** Tailscale JSON Parsing → JSON parsing exception handling yok, malformed JSON crash riski → `JsonDocument.Parse` metodu doğrudan çağrılıyor. Ancak çağrı yapan `ProbeAsync` metodunda tüm istisnaları yakalayan `catch (Exception ex)` bloğu olduğu için çökme yaşanmıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleStatusProbe.cs:82-120` ✅ **FIXED**

**39.** Test Data Hardcoded → Sanitizer testleri sadece sabit örnekler kullanıyordu → Generated/randomized sensitive JSON values test edildi; redaction'ın tek bir hardcoded fixture'a bağlı kalmadığı doğrulanıyor → `f:\cerberus-repos\cerberus-windows-agent\tests\Cerberus.Agent.Core.Tests\SanitizerTests.cs` ✅ **FIXED**

**40.** Test Organization → Parallel execution açıkça konfigüre edilmemişti → Core test projesine `xunit.runner.json` eklendi ve assembly/test collection parallelization açık hale getirildi; gerçek live/acceptance suite ayrımı hâlâ ayrı acceptance harness kapsamındadır → `f:\cerberus-repos\cerberus-windows-agent\tests\Cerberus.Agent.Core.Tests\xunit.runner.json` ✅ **FIXED**

---

## 📊 ÖZET

**Toplam Bulgu**: 47 adet  
- 🔴 **Kritik (P0)**: 5 bulgu → 5 FIXED
- ⚠️ **Yüksek (P1)**: 34 bulgu → 33 FIXED, 1 BLOCKED / SERVICE LIFECYCLE DECISION
- ⚠️ **Orta (P2)**: 8 bulgu → 7 FIXED, 1 PARTIAL / LIVE ACCEPTANCE REQUIRED

**Genel Skor**: 5.5/10 ⭐⭐½  

---

## 🔍 KOD YAPISI VE MANTIKSAL DARBOĞAZLAR HAKKINDA ÖNERİLER

### 1. Bootstrap İmza Doğrulama Zafiyeti (CRITICAL)
- **Sorun**: `BootstrapDescriptorClient.FetchAsync` üzerinde yapılan kontrol yalnızca imzanın boş olmadığını doğrulamaktadır. Kriptografik bir doğrulama (RSA/ECDSA veya Sertifika Zinciri doğrulaması) yapılmamaktadır.
- **Çözüm**: Backend tarafında descriptor imzalanmalı, Ajan üzerinde ise public key sertifikası gömülü (embedded) olarak tutularak `RSASignaturePadding.Pkcs1` ile imza doğrulanmalıdır.

### 2. Eşzamanlı/Paralel Komut Çalıştırma (Command Concurrency)
- **Sorun**: Ajan, backend'den gelen komutları sırayla (`foreach` içinde `await` ile) çalıştırmaktadır. Uzun süren bir komut (örneğin büyük bir yükleme süreci), kuyruktaki diğer tüm hafif komutları bloklamaktadır.
- **Çözüm**: Komut çalıştırma işlemleri arka planda çalışan bir `Task` kuyruğuna (örn. `Channel<T>` veya `Task.Run`) devredilmeli ve eşzamanlı limitlere (concurrency limits) göre paralel çalıştırılmalıdır.

### 3. Loglama ve SSD Ömrü (Disk I/O)
- **Sorun**: Telemetry verileri her değiştiğinde veya yeni olay eklendiğinde `OfflineTelemetryBuffer` diske tüm dosyayı yazmaktadır. Sık güncellemeler disk ömrünü (SSD) tüketebilir.
- **Çözüm**: In-memory cache kullanılmalı ve sadece belirli aralıklarla (periodic write) veya kritik olaylarda diske yazma işlemi (flush) tetiklenmelidir.

### 4. Test Altyapısında Dependency Injection
- **Sorun**: Testler `LocalUserCommandHandlers.CreateDefaultHandlers()` gibi statik oluşturucuları ve yansıtma (reflection) yöntemlerini kullanarak bağımlılıkları yönetmeye çalışmaktadır.
- **Çözüm**: Bağımlılıkların (MutationGuard, SecretStore, vb.) arayüzler (interface) aracılığıyla constructor injection ile geçilmesi, test edilebilirliği ve kod kalitesini artıracaktır.

### 5. ACL İzinlerindeki Yarış Durumları (DPAPI & Tailscale)
- **Sorun**: `DpapiSecretStore.cs` ve `TailscaleEnsureConnectedHandler.cs` dosyalarında hassas/kriptografik veriler diske yazıldıktan hemen sonra `LockDownAcl` çağrılarak dosya izinleri kısıtlanmaktadır. Dosyanın oluşturulma anı ile izinlerin kısıtlanma anı arasında geçen milisaniyelik sürede (race condition) makinedeki yetkisiz diğer süreçler/kullanıcılar bu verileri okuyabilir.
- **Çözüm**: Dosya oluşturulurken geçici kısıtlı ACL izinleri veya `FileStream` ile açılan özel `FileSecurity` parametreleri doğrudan dosya oluşturma anında (creation time) belirlenmelidir ya da dosya önceden oluşturulup ACL ayarlandıktan sonra içeriği yazılmalıdır.

### 6. RetryHelper'daki Kısa Devre ve İstek Spamı Riski
- **Sorun**: `RetryHelper.IsTransientError` metodunda `ex is HttpRequestException` ifadesinin en başta kısa devre yapması sebebiyle, kalıcı HTTP istemci hataları (400, 401, 403, 404 vb.) bile transient olarak değerlendirilip yeniden denenmektedir. Bu durum sunucuda gereksiz yük ve spam oluşturmaktadır.
- **Çözüm**: `ex is HttpRequestException` kontrolü kaldırılmalı ve doğrudan `ex is HttpRequestException hre && IsRetryableStatusCode(hre)` ifadesi kullanılmalıdır.

### 7. Otomatik Güncelleme ve Windows Dosya Kilidi (Update Locking)
- **Sorun**: `AgentUpdateCoordinator` güncellemeyi stage ediyor ancak uygulamıyor. Ayrıca `AgentUpdateStager.ApplyStagedUpdateAsync` metodunda çalışan ajanın kendi binary dosyasının (`Environment.ProcessPath`) üzerine doğrudan kopyalama yapılmaya çalışılıyor. Windows işletim sistemi çalışan süreçlerin binary'lerini kilitlediği için bu işlem her zaman `IOException` ile başarısız olacaktır.
- **Çözüm**: Çalışan dosyayı doğrudan ezmek yerine, mevcut binary ismi değiştirilmeli (örn. `.old` olarak yeniden adlandırılmalı - Windows buna izin verir), ardından yeni binary hedef yola kopyalanmalıdır. Ayrıca güncellemeyi uygulayıp servisi yeniden başlatacak bağımsız bir launcher/watchdog süreci entegre edilmelidir.
