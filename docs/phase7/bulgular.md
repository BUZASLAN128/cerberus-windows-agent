# CERBERUS WINDOWS AGENT - PHASE 7F BULGULAR VE KOD DENETİMİ

**Tarih**: 2026-05-22  
**Kapsam**: Production runtime, security, data integrity, test quality  
**Format**: Sorun → Neden → Sonuç → Dosya Yolu  

---

## 🔴 KRİTİK BULGULAR (P0)

**1.** Revoke + Clear Credentials → Backend response ile agent kalıcı kill edilebilir, confirmation yok → confirmation doğrulaması başarısız olsa bile `HeartbeatControlAction.Stop` dönülerek heartbeat döngüsü tamamen sonlandırılıyor ve ajan devre dışı kalıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\HeartbeatResponseHandler.cs:33-48` ❌ **NOT FIXED**

**2.** Offline Buffer File Corruption → Crash durumunda file corrupt, partial write riski, atomic write yok → Telemetry verileri diske doğrudan yazılıyordu. Artık temp dosyasına yazılıp atomic move işlemi yapılıyor ve bozuk dosyalar karantinaya alınıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\OfflineTelemetryBuffer.cs:107-114` ✅ **FIXED**

**3.** Command Execution Exception → DispatchAsync exception fırlatırsa loop catch'e düşer, diğer commands çalışmaz → Heartbeat loop içerisindeki `foreach` döngüsünde bireysel command'ler için try-catch bulunmuyor, hata durumunda döngü kesiliyor ve sonraki komutlar işlenemiyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\HeartbeatLoop.cs:149-161` ⚠️ **PARTIAL** (Dış catch bloğu var ama iç döngü kesilmeye devam ediyor)

**4.** Service Credential Promotion → User-scope credentials machine-scope'a kopyalanıyor, cryptographic verification yok → Kopyalama işlemi yapılıyor ancak doğrulama sadece basit string metadata kontrolleri ile yapılıyor, kriptografik imza doğrulaması veya hash bütünlüğü doğrulaması eksik → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Actions\AgentServiceProvisioning.cs:88-91` ⚠️ **PARTIAL**

**43.** DPAPI Secret Store File ACL Race Condition → `DpapiSecretStore.cs` dosyasında secrets dosyası diske yazılırken (`WriteAllBytesAsync`) varsayılan miras alınan izinlerle oluşturulur; kısıtlayıcı ACL izinleri (`LockDownAcl`) ancak dosya yazıldıktan sonra uygulanır → Dosya yazma ve ACL sıkılaştırma adımları arasında mikrosaniyelik bir yarış durumu (race condition) bulunmaktadır. Bu kısa süreli pencerede makinedeki yetkisiz diğer kullanıcılar veya süreçler dosyayı okuyabilir; makine kapsamı (Machine scope) kullanıldığında bu veri DPAPI üzerinden çözülüp token'lar ele geçirilebilir → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Security\DpapiSecretStore.cs:79-80` ❌ **NOT FIXED**

---

## ⚠️ YÜKSEK RİSK (P1)

**5.** Offline Buffer Pruning → Buffer limit aşınca kritik events önce atılıyor (priority=5), snapshot priority=10 → Düşük öncelikli snapshot verileri tutulurken kritik güvenlik/denetim olayları daha önce diskten siliniyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\OfflineTelemetryBuffer.cs:127-135` ❌ **NOT FIXED**

**6.** Snapshot Timing Race → nextSnapshotAt local state, restart olursa DateTimeOffset.MinValue, ilk heartbeat'te snapshot gönderilir → `nextSnapshotAt` değişkeni `DateTimeOffset.MinValue` olarak başlatılıyor, bu yüzden servis her başladığında ilk heartbeat'te hemen snapshot gönderilip flood yapılıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\HeartbeatLoop.cs:65` ❌ **NOT FIXED**

**7.** Command Execution Blocking → Commands sıralı çalışıyor, uzun command diğerlerini blokluyor → Bireysel komutlar `await` ile ardışık şekilde bekleniyor. Paralel yürütme veya arka plan iş kuyruğu mantığı bulunmuyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\HeartbeatLoop.cs:149-161` ⚠️ **PARTIAL**

**8.** Update Handling Failure → Update failure sessizce ignore ediliyor, backend status bilinmiyor → Güncelleme başarısızlıkları loglanıyor ve isteğe bağlı `_updateFailureReporter` çağrılıyor ancak backend'e durum raporlaması veya otomatik geri bildirim garantisi zayıf → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\HeartbeatResponseHandler.cs:72-91` ⚠️ **PARTIAL**

**9.** Telemetry Buffer Disk I/O → Her enqueue/dequeue'da full file read/write, 200 entry * 64KB = 12.8MB → Bellek içi tamponlama (in-memory caching) veya toplu yazma (batching) yok; her işlemde tüm dosya diske yazılıp okunuyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\OfflineTelemetryBuffer.cs:95-104` ❌ **NOT FIXED**

**10.** Password Encryption Key Rotation → Public key payload'dan geliyor, key rotation mekanizması yok → Gelen payload üzerindeki public key doğrudan kullanılıyor, yerel olarak anahtar rotasyonu ve geçersiz kılma mantığı yok → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs:267-275` ❌ **NOT FIXED**

**11.** Bootstrap Descriptor Revocation (CRITICAL SECURITY VULNERABILITY FOUND) → Kriptografik imza doğrulaması hiç yapılmıyor! Sadece imza alanının boş olmaması kontrol ediliyor → `BootstrapDescriptorClient.FetchAsync` metodunda sadece `string.IsNullOrWhiteSpace(parsed.Signature)` kontrolü yapılıyor. RSA veya sertifika doğrulama kodu bulunmuyor, bu da MITM/Spoofing saldırılarına kapı açıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\BootstrapDescriptor.cs:40-41` ❌ **NOT FIXED**

**12.** Update Manifest Download → 200MB artifact download progress yok, timeout 30 saniye (çok kısa) → `ServiceMode.cs` içinde HttpClient timeout değeri sert kodlanmış (30s) ve indirme esnasında progress raporlama yapılmıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\AgentUpdateStager.cs:185-220` ❌ **NOT FIXED**

**13.** Telemetry Section Exception → Section collector exception'ı snapshot'ı kırabilir, partial snapshot riski → Hatalar yakalanmıyordu. Artık `TelemetrySectionCapture` her bir toplayıcının hatasını `try-catch` ile izole ediyor ve hata durumunu snapshot verisinde failed olarak işaretliyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\Telemetry\TelemetrySectionCapture.cs` ✅ **FIXED**

**16.** Password Generation Weak → Base64 + "aA1!" pattern, predictable, brute force riski → Sabit pattern kullanılıyordu. Artık `RandomNumberGenerator` ile kriptografik olarak güvenli, karmaşık ve rastgele şifreler üretiliyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs:240-241` ✅ **FIXED**

**17.** Local User Rate Limiting → Command handler'lar rate limiting yok, back-to-back user create/delete → Komut işleyicilerde istek sıklığı doğrulaması veya cooldown mekanizması bulunmuyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs:30-35,60-65,90-95` ❌ **NOT FIXED**

**18.** Local User Description → Description field validation yok, length limit yok (Windows: 256 karakter) → Windows SAM veritabanı limitleri kontrol edilmiyordu. Artık açıklama alanı maksimum 256 karakter olacak şekilde kırpılıyor ve doğrulanıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs:244-247` ✅ **FIXED**

**19.** Local User SID Exception → Exception swallowing, SID retrieval failure sessizce ignore ediliyor → Hata oluştuğunda exception loglanmak yerine catch edilerek doğrudan `null` dönülüyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs:249-260` ❌ **NOT FIXED**

**20.** Username Validation Regex → İki farklı regex pattern, complex validation logic, pattern dokümantasyonu yok → Kullanıcı adı doğrulamasında hem genel kurallar hem de yönetilen hesap desenleri için iki ayrı karmaşık regex kullanılıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs:277-280,282-285` ❌ **NOT FIXED**

**21.** Password Key Validation → Public key validation yok, key size validation yok (min 2048 bit) → Gelen anahtarlar doğrudan kabul ediliyordu. Artık PEM formatı kontrol ediliyor, anahtar boyutu doğrulanıyor (>=2048 bit) ve SHA256 parmak izi (fingerprint) doğrulaması yapılıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Ad\LocalUserCommandHandlers.cs:267-275` ✅ **FIXED**

**22.** Update Rollback Plan → Update staging başarılı olursa sadece log yazılıyor, rollback planı yok → staged edilen güncellemelerin diski doldurmasını önlemek için eski sürümlerin temizlenmesi (cleanup) ve güncelleme sonrası çalışmama durumunda otomatik geri alma (rollback) planı bulunmuyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Updates\AgentUpdateCoordinator.cs:20-30` ❌ **NOT FIXED**

**23.** Update Apply Validation → planPath validation yok, file existence check yok, elevation check yok → Path traversal engellemek için staging root altındaki dosyalar doğrulanıyor fakat `UpdateApplyMode.RunAsync` içinde `target` parametresi hem hedef hem de izin verilen hedef olarak iki kez geçirilerek kontrol baypas ediliyor. Ayrıca yönetici yetkisi (elevation) doğrulaması eksik → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Updates\UpdateApplyMode.cs:8-16` ⚠️ **PARTIAL**

**24.** Telemetry Section Error → Section capture exception durumunda tüm snapshot fail olur, partial snapshot support yok → Hatalar yakalanmıyordu. (Bulgu 13 ile aynı) Artık yakalanıp partial snapshot destekleniyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Telemetry\WindowsTelemetryCollector.cs:27-38` ✅ **FIXED**

**25.** Telemetry Section Catalog → Hardcoded section catalog, dynamic configuration yok, feature flag support yok → Telemetry bölümleri kodda statik bir listede tanımlanmış durumda, backend'den gelen yönergelere göre dinamik olarak açılıp kapatılamıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Telemetry\WindowsTelemetryCollector.cs:12-15` ❌ **NOT FIXED**

**27.** RSA Key Persistence → Key generation only, persistence yok, key lifecycle management yok → `RsaKeyManager` sadece anahtar çifti oluşturma işlevi sunuyor; yerel depolama, rotasyon ve yaşam döngüsü yönetimini çağıran sınıflara bırakıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Security\RsaKeyManager.cs:5-12` ❌ **NOT FIXED**

**29.** Log Sanitizer Performance → 6 farklı regex pattern, her log entry için tüm regex'ler çalıştırılıyor → Her log satırı için ardışık olarak 6 farklı Regex.Replace çağrısı yapılıyor. Hızlı geçiş (fast-path) kontrolleri yok → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\Sanitizer.cs:5-45` ❌ **NOT FIXED**

**30.** Log Sanitizer Coverage → Pattern-based redaction only, context-aware redaction yok, structured data redaction yok → Sadece statik regex kalıpları eşleştiriliyor. Yapılandırılmış JSON veya zengin bağlamlı logları algılayıp güvenli hale getirme mantığı yok → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\Sanitizer.cs:47-60` ❌ **NOT FIXED**

**31.** File Logger Rotation → Log rotation yok, file size limit yok, retention policy yok → `StreamWriter` ile dosyanın sonuna sürekli ekleme yapılıyor. Boyut sınırı kontrolü veya arşivleme/silme adımları bulunmuyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\AgentFileLogger.cs:20-30` ❌ **NOT FIXED**

**33.** Tailscale Auto Execution → Command file oluşturuluyor ama otomatik execute edilmiyor, manual intervention required → Kodda güvenlik veya debug amacıyla `tailscale up` komutunun otomatik çalıştırılmaması, sadece `.cmd` dosyası olarak diske yazılması tercih edilmiş → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleEnsureConnectedHandler.cs:40-55` ❌ **NOT FIXED**

**34.** Tailscale Status Caching → Her probe'da external process spawn ediliyor, result caching yok → Her durum kontrolü yapıldığında yeni bir `tailscale status --json` süreci başlatılıyor. Önbellekleme (caching) veya throttle mantığı yok → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleStatusProbe.cs:20-80` ❌ **NOT FIXED**

**35.** Tailscale Command Security → Plain text auth key file'da saklanıyor, no encryption for auth key → Diske yazılan `.cmd` dosyasına kimlik doğrulama anahtarı (auth key) açık metin olarak yazılıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleUpCommand.cs:8-20` ❌ **NOT FIXED**

**36.** Tailscale ACL Lockdown → ACL protection only, administrators still have access, no encryption → Dosyaya sadece SYSTEM ve Administrators grubuna yetki verilmiş fakat yerel yöneticiler (Admins) dosyayı okuyarak açık metin anahtarı görebilir → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleEnsureConnectedHandler.cs:75-95` ❌ **NOT FIXED**

**38.** Test Coverage Incomplete → Test kapsamı yetersiz, kritik yollar test edilmemiş ve güvenlik doğrulamaları eksik → Birim testleri ağırlıklı olarak izole edilmiş doğrulayıcı testleridir; gerçek işletim sistemi yolları veya uçtan uca senaryolar test edilmemiştir → `f:\cerberus-repos\cerberus-windows-agent\tests\Cerberus.Agent.Core.Tests\LocalUserCommandHandlersTests.cs:5-50` ❌ **NOT FIXED**

**41.** Test Assertions Limited → Basic assertion only, missing comprehensive verification, no side effect validation → Test iddiaları (assertions) sadece dönen durumların basitçe kontrol edilmesi şeklindedir (örn. Status = "FAILED") → `f:\cerberus-repos\cerberus-windows-agent\tests\*` ❌ **NOT FIXED**

**42.** Test Infrastructure Mock → Limited mock/fake infrastructure, no dependency injection for testing → Test projesinde dependency injection kullanılmamakta, nesneler doğrudan static metotlarla veya yansıtma (reflection) ile oluşturulmaktadır → `f:\cerberus-repos\cerberus-windows-agent\tests\*` ❌ **NOT FIXED**

**44.** No Auto-Update Execution → `AgentUpdateCoordinator` yeni güncellemeleri başarıyla indirip staging dizinine hazırlar ancak bu güncellemenin otomatik uygulanmasını tetikleyen bir mekanizma yoktur → Ajan servis döngüsünde güncelleme planı hazırlandıktan sonra süreci kapatıp yeni güncellemeyi `--apply-update-plan` parametreleriyle çalıştıracak bir süreç başlatıcı veya servis tetikleyicisi yazılmamıştır → Güncellemeler staging dizininde bekler ve manuel müdahale olmadan asla uygulanmaz → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Updates\AgentUpdateCoordinator.cs:22-28` ❌ **NOT FIXED**

**45.** Retry Helper Spam on Client Errors → `RetryHelper.cs` dosyasındaki `IsTransientError` metodu, mantıksal bir kısa devre hatası nedeniyle tüm HTTP istemci istisnalarını geçici hata (transient) kabul eder ve yeniden dener (retry). `IsRetryableStatusCode` metodu ölü kod (dead code) durumundadır → `ex is HttpRequestException || ... || (ex is HttpRequestException hre && IsRetryableStatusCode(hre))` ifadesinde ilk kısım her zaman doğru (`true`) olacağı için `IsRetryableStatusCode` kontrolü asla çalıştırılmaz → `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found` gibi kalıcı istemci hatalarında bile gereksiz yere yeniden deneme (retry) yapılarak sunucu tarafında istek spam'ine yol açılır → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\RetryHelper.cs:73-88` ❌ **NOT FIXED**

**46.** Windows File Lock on Active Binary Update → `AgentUpdateStager.cs` üzerinde güncellemeyi uygularken `File.Copy(..., overwrite: true)` metoduyla çalışan aktif ajanın yürütülebilir dosyası (`Environment.ProcessPath`) üzerine yazmaya çalışılır → Windows işletim sisteminde çalışan bir sürecin yürütülebilir dosyası (binary) işletim sistemi tarafından kilitlenir ve doğrudan üzerine yazılamaz → Güncelleme uygulaması `IOException` (Sharing Violation/Access Denied) fırlatarak başarısız olur. Standart yaklaşım çalışan yürütülebilir dosyayı önce yeniden adlandırmak (rename) ve ardından yenisini kopyalamaktır → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\AgentUpdateStager.cs:161-172` ❌ **NOT FIXED**

**47.** Tailscale Command File ACL Race Condition → `TailscaleEnsureConnectedHandler.cs` dosyasında, geçici ve hassas Tailscale authkey içeren `.cmd` ve `.json` dosyaları diske yazıldıktan sonra ACL izinleri kısıtlanır → Dosyalar `File.WriteAllTextAsync` ile ortak bir uygulama dizininde varsayılan izinlerle oluşturulur ve hemen ardından `LockDownAcl` çağrılır → Dosyaların oluşturulması ile ACL'lerin kısıtlanması arasında geçen sürede makinedeki diğer düşük yetkili kullanıcılar veya süreçler dosyayı okuyarak açık metin durumundaki Tailscale authkey değerini ele geçirebilir → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleEnsureConnectedHandler.cs:94-109` ❌ **NOT FIXED**

---

## ⚠️ ORTA RİSK (P2)

**14.** Network Telemetry IP Leak → Private IP adresleri backend'e gönderiliyor, sanitization yok → Ağ arabirimlerinin özel IP adreslerini hiçbir maskeleme yapmadan backend'e iletiyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Telemetry\NetworkTelemetrySectionCollector.cs:18-26` ❌ **NOT FIXED**

**15.** Service Uninstall Credential → Machine secrets user'a sync edilemiyor, silent failure → Kaldırma (uninstall) işlemi yönetici yetkisi ile (Admin context) çalıştığı için, üretilen DPAPI anahtarları kaldırma işlemini yürüten kullanıcının dizini yerine Admin AppData'sına kaydediliyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Actions\AgentServiceProvisioning.cs:95-102` ❌ **NOT FIXED**

**26.** Telemetry Context Immutable → Immutable record (iyi) ama LastHeartbeat nullable, null check gerekiyor → `LastHeartbeat` nullable'dır ve kısa devre `&&` mantığıyla korunuyor olsa da compiler uyarısı verebilecek şekilde `context.LastHeartbeat.ServerTimeUtc` dereference ediliyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.App\Telemetry\WindowsTelemetryContext.cs:5-8` ⚠️ **PARTIAL**

**28.** Secret Store Scope → Sadece 2 scope: User ve Machine, no granular scope support → Kriptografik depolama doğrudan DPAPI'ye dayanıyor, çok kiracılı (multi-tenant) mantıksal yalıtım veya ayrı anahtar kasası desteği bulunmuyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Security\SecretStoreScope.cs:3-7` ❌ **NOT FIXED**

**32.** File Logger Concurrent → Single _gate lock for all operations, potential contention in high-volume logging → Tüm log yazma ve konsol çıktıları tek bir lock nesnesi (`_gate`) üzerinden senkronize edilerek iş parçacıklarını blokluyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Core\AgentFileLogger.cs:45-55` ❌ **NOT FIXED**

**37.** Tailscale JSON Parsing → JSON parsing exception handling yok, malformed JSON crash riski → `JsonDocument.Parse` metodu doğrudan çağrılıyor. Ancak çağrı yapan `ProbeAsync` metodunda tüm istisnaları yakalayan `catch (Exception ex)` bloğu olduğu için çökme yaşanmıyor → `f:\cerberus-repos\cerberus-windows-agent\src\Cerberus.Agent.Integrations.Tailscale\TailscaleStatusProbe.cs:82-120` ✅ **FIXED**

**39.** Test Data Hardcoded → Hardcoded test data, no random/fuzzing tests, edge case coverage limited → Sanitizer testlerinde sadece önceden tanımlanmış sabit metinler kullanılıyor. Fuzzing veya rastgele veri testi yok → `f:\cerberus-repos\cerberus-windows-agent\tests\Cerberus.Agent.Core.Tests\SanitizerTests.cs:10-50` ❌ **NOT FIXED**

**40.** Test Organization → Tüm testler aynı projede, no test categorization, no parallel execution → xUnit projelerinde entegrasyon ve birim testleri tek bir projede toplanmış, paralel çalışma veya gruplama konfigürasyonu yapılmamış → `f:\cerberus-repos\cerberus-windows-agent\tests\*` ❌ **NOT FIXED**

---

## 📊 ÖZET

**Toplam Bulgu**: 47 adet  
- 🔴 **Kritik (P0)**: 5 bulgu → 1 FIXED, 2 PARTIAL, 2 NOT FIXED  
- ⚠️ **Yüksek (P1)**: 34 bulgu → 5 FIXED, 4 PARTIAL, 25 NOT FIXED  
- ⚠️ **Orta (P2)**: 8 bulgu → 1 FIXED, 1 PARTIAL, 6 NOT FIXED  

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

