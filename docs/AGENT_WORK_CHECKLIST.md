# Ajan işi kontrol listesi

`AGENTS.md` içindeki Work Rules kurallarının işaretlenebilir hâli. Her ajan işi
için PR açıklamasına veya teslim raporuna kopyalanır. İşaretlenmeyen madde
raporda `NOT RUN` olarak yazılır.

## Durum satırı (her raporun başında)

```text
Ajan durumu - head <sha>
İmzasız build (resmi hat): PASS / FAIL / NOT RUN
VM106 smoke:               PASS / FAIL / NOT RUN
İmza:                      PASS / FAIL / NOT RUN
PC n/10, VM n/10:          <n>/10, <n>/10
Normal dönüş ve feed:      PASS / FAIL / NOT RUN
Yayın:                     PASS / FAIL / NOT RUN
Engel: <...>   Sıradaki: <kim, ne>
```

"Ajan tamam" yalnızca gereken her satır PASS iken denir. Merge, geçerli imza
veya çalışan servis kabul değildir.

## 1. İş bitti: imzasız build

- [ ] Head: `<sha>`
- [ ] `scripts/build-agent-public-release.ps1 -Channel dev -AllowUnsignedDevBuild`
      ile resmi lab dışı hattan helper, MSI ve setup; etkilenen her profil
      (ortak kodda desktop ve server)
- [ ] Lab veya destek build'i sayılmadı; release gate lab dışı build'de çalıştı
- [ ] CI build adımları hatada duruyor; dev push'unda yayın yapan workflow yok
- [ ] MSI'daki ProductVersion, profil ve kanal birleştirilen kodla eşleşiyor;
      MSI sha256: `<hash>`

## 2. Aynı gün VM106 smoke (owner PC ilk deneme değil)

- [ ] Sahada kurulu sürümün üstüne yükseltme olarak kuruldu
- [ ] Kurulum çıkış kodu başarılı
- [ ] Kurulu ve çalışan servis sürümü yeni sürüm
- [ ] Kayıt, kimlik anahtarları, korumalı geçmiş ve sıra sınırları korundu
- [ ] Taze heartbeat ve backend/API'de kalıcı kayıt görüldü
- [ ] Panelden bir komut ACK aldı
- [ ] Hata durumları hata koduyla görünüyor
- [ ] Kaldırma ve temizlik yalnızca atılabilir test durumunda yapıldı
- [ ] Güvenli VM durumu yoksa smoke `FAIL: blocked` yazıldı, PC'ye geçilmedi

## 3. Güncelleme kodu değiştiyse

- [ ] Mevcut dev güven yolundan bir gözetimsiz güncelleme ve hatadan toparlanma
- [ ] İmza, kanal ve replay kontrolleri kapatılmadı; lab yolu etiketlendi
- [ ] Manifestin kendi `artifact_url` adresi LAN dışından indirildi
- [ ] Paket boyutu ajanın indirme sınırının altında

## 4. İmza oturumu

- [ ] Aynı head'de 1-3 PASS
- [ ] Girdiler ve geri dönüş planı donduruldu
- [ ] İmza, merge ve yayın ayrı onaylar olarak istendi

## 5. Kabul (güncellemeyi etkileyen işler)

- [ ] Donmuş adayda PC 10/10 ve VM106 10/10; her geçişte kontrollü hata,
      otomatik toparlanma, elle müdahale 0
- [ ] Sayılar hedef makinenin kendi kayıtlarından okundu
- [ ] Bootstrap ve elle dönüş sayılmadı; davranış değiştiyse yeniden kanıtlandı
- [ ] Zamanlı kampanyadan önce iki hedef, owner erişimi, feed girdileri ve
      imzalı dönüş hazır; yükleme, inceleme, canary, gözlemci ve dönüş tek
      bütçeye sığıyor

## 6. Yayın

- [ ] Normal dönüş ve feed sürekliliği ayrıca kanıtlandı
- [ ] Owner yayın onayı verdi

## Her işte

- [ ] Test düzeneği işi ürün ilerlemesi gibi raporlanmadı
- [ ] Yetkili betikler korumalı klasörden, doğrulanan baytlarla çalıştı
- [ ] Birim testleri gerçek ProgramData'ya yazmadı; uzak/QGA yardımcı adları
      komut kısaltmalarıyla çakışmıyor
- [ ] Gerekli exact-head incelemeler aday üzerinde bir kez yapıldı; eksik
      çalışma kanıtını ek inceleme kapatmaz
