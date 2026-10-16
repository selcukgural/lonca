# Lonca — Agent-Native Versiyon Kontrol Sistemi

Tasarım dokümanı.

> Durum: v0.3 · 2026-10-16 — dört fazın ilk uygulaması tamam (bkz. §11).
> v0.1: claude.ai üzerindeki tasarım tartışması. v0.2: Claude Code incelemesi ve proje kararları. v0.3: uygulama durumu ve sapmalar.
> Bu doküman Claude Code tarafından uygulama bağlamı olarak okunmak üzere yazılmıştır.

## 0. v0.1'den bu yana değişenler

- **Proje kararları** eklendi: açık kaynak, tek makinede çok agent, Git nesne formatı + köprü, isim **Lonca**, dil **Rust** (§1).
- **Kanıt ile karar ayrıldı:** build/test deterministik değildir. Bunlar imzalı *attestation* üretir; karar fonksiyonu saftır ve tüm girdileri log'dadır (§2, §5.9).
- **Zaman** karar girdisi olarak log'a yazılır; "zaman karara girmez" ifadesi kaldırıldı (§5.2).
- **Tehdit modeli ve üç çalışma modu** (iş birlikçi / sertleştirilmiş iş birlikçi / izole) eklendi. Tek makinede tam aracılık ancak işletim sistemi sınırıyla sağlanır (§3).
- **Gözlem yoksa kirli say:** Gözlenemeyen oturum varsayılan olarak kirli kabul edilir. Harness'lar güven seviyelerine ayrıldı (§3.1, §3.2).
- **Yerel güven sınırı:** Sertleştirilmiş modda daemon ayrı bir sistem kullanıcısıyla çalışır ve nesne deposunun sahibidir. Hook programı root'a aittir. sudo durumu kontrol edilir ve bütünlük izlenir (§3.3).
- **İmza modeli:** agent'ların uzun ömürlü anahtarı yoktur, işlemlerini daemon imzalar. İnsan imzası kullanıcı varlığı (dokunuş) ister (§5.4).
- **Taint → köken (provenance):** kirlilik oturumla birlikte içerikte de taşınır. Okuma gözlemi modelin beyanından değil, harness'tan veya proxy'den gelir (§5.10).
- **Lease:** beklemesiz ve hepsi-ya-hiç (deadlock yok). Ekleme ve import kiralaması eklendi, imza değişikliği kuralı tanımlandı (§5.7).
- **Merge queue** eklendi: kanıt, birleşmiş durum için üretilir (§5.8).
- **Beyan yapısal hale geldi;** serbest metin `intent` karar girdisi değildir (§5.9, §7).
- **Test bütünlüğü ve doğrulama-kritik yollar** eklendi (§5.9).
- **Undo, telafi edici işlemdir;** sızan sırlar için `blob.redact` eklendi (§5.3).
- **Politika** kod branch'lerinden ayrı, korumalı bir ref'te durur; Cedar önerildi (§5.6).
- **Auditor Faz 1'e çekildi;** log başı uzak depoya çapalanır (§5.2, §5.13).
- **Agent arayüzü:** MCP + CLI (§5.11).
- **Maliyet kotaları** eklendi (§5.9, §5.14).

## 1. Amaç

Git benzeri, **deterministik çekirdeğe sahip** bir versiyon kontrol sistemi. Kimlik, yetki, işlem ve eşzamanlılık modeli ise baştan **AI agent'larını** hesaba katar. Bu, Git'in üstüne bir entegrasyon değil, agent'lar düşünülerek tasarlanmış yeni bir VCS'tir. Depolama formatı ise benimsenmeyi kolaylaştırmak için Git ile uyumlu kalır.

Bugünkü sorun: Git ve GitHub/GitLab'ın güvenlik ve izin modeli "her yazan bir insandır" varsayımına dayanır. Agent'lar genelde bir insanın token'ıyla çalışır, kayıtlarda görünmez ve yetkileri gereğinden geniştir. Force push, branch silme ve yetki değişikliği gibi işlemler denetlenebilir biçimde geri alınamaz.

### Kararlar

| Konu | Karar |
|---|---|
| Hedef | Açık kaynak proje |
| Birincil senaryo | Tek geliştirici makinesinde 10–20 eşzamanlı agent. Gatekeeper yerel bir daemon'dur. Ekip sunucusu sonraki aşamadır. |
| Git uyumu | İçerik Git nesne formatındadır. Op log ve meta veriler Git nesneleri olarak özel ref'lerde durur. GitHub'a push/pull yapılabilir. |
| İsim | **Lonca**: zanaatkâr loncası. Nizamname = politika; usta–kalfa–çırak = yetki zinciri; ürün denetimi = doğrulama. CLI komutu `lonca`. GitHub organizasyonu `lonca-dev` veya `lonca-vcs` (ikisi de 2026-10-16'da boştu; `lonca` hesabı alınmış). Marka araması henüz yapılmadı. |
| Uygulama dili | Rust |

### Hedefler

- Çekirdek tamamen deterministiktir; bütünlük kriptografik olarak korunur.
- Her işlem (yazma, silme, revert, yetki verme/alma) kayıtlı, imzalı ve geri sarılabilirdir.
- 10–20 agent aynı dosyada, farklı fonksiyonlar üzerinde paralel çalışabilir.
  - **Güvence altında:** kayıp güncelleme yoktur, sessiz üzerine yazma yoktur ve trunk'a giren her durum *o durum üzerinde* doğrulanmıştır.
  - **Güvence dışında:** testlerin yakalamadığı anlamsal hatalar.
- Çakışmalar sırasıyla deterministik olarak, agent müzakeresiyle, kurallarla ve en son insanla çözülür.
- Halüsinasyon ve prompt injection'a karşı yapısal önlemler bulunur.
- Kurallar ve denetim mekanizması AI'dan bağımsızdır.

### Hedef olmayanlar

- Versiyon kontrolünü AI üzerinden yürütmek. **AI hiçbir zaman bütünlük yolunda değildir**; yalnızca öneren, özetleyen ve işaretleyen bir danışman katmandır.
- Git'in nesne modelini baştan icat etmek. İçerik adresli Merkle DAG korunur.
- v1'de çok kullanıcılı barındırma ve dağıtık uzlaşma. Her repo için op log'un tek bir sıralayıcısı vardır: yerel daemon.

## 2. Temel İlkeler

1. **Referans monitörü (complete mediation):** Agent'lar depoya asla doğrudan yazmaz. Her işlem tek bir kapı bekçisinden (Gatekeeper) geçer. Agent önerir, bekçi karar verir. Tek makinede bu ilkenin gerçekten uygulanması için işletim sistemi sınırı gerekir (§3).
2. **Beyana değil kanıta bak:** Agent'ın "testleri çalıştırdım" gibi iddiaları kabul edilmez; doğrulama bekçi tarafından izole ortamda yeniden yapılır.
3. **Kanıt ile karar ayrıdır:** Kanıt üreticileri (build, test) deterministik olmayabilir ve sonuçlarını imzalı attestation olarak kaydeder. Karar fonksiyonu saftır ve tüm girdileri log'dadır; aynı girdiler her zaman aynı kararı verir.
4. **Model beyanı ≠ harness gözlemi:** Modelin kendisi hakkında söylediğine değil, onu çalıştıran ortamın (harness, sandbox, proxy) veya daemon'un gözlemine güvenilir.
5. **En az yetki, süreli yetki, varsayılan red:** Yetkiler repo düzeyinde değil yetenek (capability) düzeyinde verilir, süresi dolar ve asla genişleyemez. Bilinmeyen işlem tipi, kapsam veya yol reddedilir.
6. **Yetki yukarıdan gelir:** Agent yetki *isteyebilir* ama yetki yaratamaz veya genişletemez. Yalnızca kendi yetkisinin daraltılmış bir alt kümesini kendi alt oturumlarına (alt-agent'lar) devredebilir.
7. **Kurallar da korunur:** Politikalar kod olarak sürümlenir; agent'lar politikaya yazamaz.
8. **Bekçinin bekçisi:** Bağımsız bir denetçi, işlem günlüğünü sürekli yeniden oynatarak kuralların uygulandığını doğrular.
9. **AI en dış katmandadır:** AI'ın ürettiği her şey (merge önerisi, çakışma çözümü) yine bekçiden geçer.

## 3. Tehdit Modeli ve Çalışma Modları

**Aktörler**
- **İnsan:** güvenilirdir, ama makinesini agent'larla paylaşır.
- **Agent:** hata yapabilir, halüsinasyon görebilir, kapsamı aşabilir ve prompt injection ile ele geçirilebilir.
- **Dış içerik** (issue, PR, web sayfası, bağımlılık metni): düşmanca kabul edilir.

**Korunan varlıklar:** trunk bütünlüğü, op log bütünlüğü, politika, insan imzaları, sırlar.

Tek makinede agent'lar kullanıcının hesabıyla çalışıyorsa nesne deposuna dosya sistemi üzerinden yazabilir ve Gatekeeper'ı atlayabilir. Bunu yazılım kuralı değil, ancak işletim sistemi sınırı engeller. Bu yüzden üç mod vardır:

| | İş birlikçi | Sertleştirilmiş iş birlikçi | İzole |
|---|---|---|---|
| Agent nerede çalışır | Kullanıcı hesabıyla, doğrudan | Kullanıcı hesabıyla; harness sandbox'ı ve agent'ın değiştiremediği hook'larla | Sandbox/container içinde; depoya, imza anahtarlarına ve sırlara erişimi yok |
| Karşı koyduğu | Kaza, halüsinasyon, kapsam taşması, çakışma | Bunlar + harness üzerinden yapılan gözlenmemiş dış okuma ve depoya yazma | Bunlar + ele geçirilmiş agent |
| Depoya doğrudan yazma | Engellenmez, **tespit edilir** (hash zinciri + çapa + Auditor) | Engellenir; depo daemon'un sistem kullanıcısına aittir (§3.3) | Engellenir |
| Gözlemi atlatma | Gözlem yok; oturum `unobserved` sayılır | Harness içinden yapılırsa engellenir; harness dışından yapılırsa tespit edilir | Engellenir |
| Kurulum maliyeti | Yok (daemon kullanıcının hesabıyla çalışır) | Tek seferlik admin kurulumu: sistem kullanıcısı, daemon, hook programı, managed settings | Container runtime veya OS sandbox |
| Harness gereksinimi | Yok | H1 veya H2 (§3.2) | Yok |

- **Önerilen varsayılan:** Harness destekliyorsa sertleştirilmiş mod. Politika, belirli görevler için izole modu zorunlu kılabilir.
- **Düz iş birlikçi modda** gözlem yoktur. Bu yüzden oturumlar `unobserved` etiketi alır ve varsayılan politika onları kirli sayar (§3.1, adım 1). Kullanıcı bu riski açıkça kabul ederek politikayı gevşetebilir.
- **Dürüst sınır:** Sertleştirilmiş modda depo korunur. Ama ele geçirilmiş bir agent, harness dışında başlatılan bir süreçle çalışma alanını değiştirebilir veya dış içerik okuyabilir. Bu engellenmez, yalnızca tespit edilir. Prompt injection'a karşı tam koruma izole moddadır.
- Sertleştirilmiş ve izole modda nesne deposunun sahibi daemon'un sistem kullanıcısıdır. Her agent yalnızca kendi çalışma alanına yazar ve önerilerini Unix soket üzerinden gönderir.

### 3.1 Sertleştirilmiş iş birlikçi mod

Amaç, aynı kullanıcı hesabı içinde atlatmayı imkânsız kılmak değil (bu mümkün değil), atlatmayı zorlaştırmak ve görünür kılmaktır. Emin olunamayan her durumda oturum kirli sayılır. Claude Code ayrıntıları 2026-10-16 tarihli belgelerle doğrulanmıştır.

1. **Gözlem yoksa kirli say (fail-closed).**
   - Oturum, başlangıç hook'u (`SessionStart`) ile daemon'a kaydolur ve düzenli heartbeat gönderir.
   - Hook yapılandırmasının hash'i oturum başında kaydedilir.
   - Heartbeat kesilirse, hook yapılandırmasının hash'i değişirse veya bir hook daemon'a ulaşamazsa oturum kirli sayılır.
   - Hook zaman aşımı, araç çağrısını engellemelidir. Claude Code'da bu `"onFailure": "block"` ile yapılır; varsayılan davranışta zaman aşımına uğrayan hook çağrıyı engellemez.
2. **Hook ayarları agent'ın değiştiremeyeceği yerde durur.**
   - Claude Code'da bunun için managed settings dosyası kullanılır: macOS'ta `/Library/Application Support/ClaudeCode/managed-settings.json`, Linux'ta `/etc/claude-code/managed-settings.json`. Bu dosyadaki anahtarları kullanıcı ve proje ayarları geçersiz kılamaz.
   - Aynı dosyaya `allowManagedHooksOnly: true` yazılır; böylece yalnızca bu dosyadaki hook'lar çalışır.
   - Belgeler dosyanın root'a ait olmasını zorunlu tutmaz; bunu kurulumumuz sağlar (`root`, 0644). Bu kilit ancak agent sudo kullanamıyorsa anlamlıdır; ayrıntılar §3.3'te.
3. **PostToolUse değil, PreToolUse.**
   - Engelleyen hook tüm araçları kapsar (matcher `*`): Bash, Read, Edit, Write, WebFetch, WebSearch ve MCP araçları.
   - Engelleme, çıkış kodu 2 ile veya `permissionDecision: "deny"` ile yapılır.
   - Temiz bir oturum dış içerik okumak isterse politika iki şeyden birini uygular: isteği reddeder ya da oturumu önce kirli işaretleyip sonra izin verir.
   - Çalışma alanı dışına yazma girişimleri (nesne deposu, `.lonca/`, harness ayarları) reddedilir.
   - PostToolUse yalnızca kayıt için kullanılır.
4. **Gözlem–etki tutarlılığı.**
   - Daemon çalışma alanını dosya sistemi olaylarıyla izler.
   - Bildirilen hiçbir araç çağrısıyla açıklanamayan bir dosya değişikliği "gözlenmemiş etkinlik" sayılır: oturum kirlenir ve olay log'a yazılır.
   - Nesne deposunda daemon dışından yapılan bir değişiklik alarm üretir.
   - Bu kontrol deterministiktir; beyan–diff tutarlılığının (§5.9) gözlemdeki karşılığıdır.
5. **Harness sandbox'ı.** Claude Code, shell komutlarını (Bash ve alt süreçleri) macOS'ta Seatbelt, Linux'ta bubblewrap ile sınırlar.
   - **Ağ:** Sandbox içindeki komutların trafiği daemon'un proxy'sine yönlendirilir (`sandbox.network.httpProxyPort`, `sandbox.network.socksProxyPort`). Her dış istek log'a yazılır ve oturumu kirletir.
   - **Yazma:** Varsayılan olarak çalışma dizini ve geçici dizinle sınırlıdır. Nesne deposu çalışma alanının dışında tutulur.
   - **Okuma:** Varsayılan olarak makinenin çoğu okunabilir, `~/.ssh` dahil. Sırlar `sandbox.filesystem.denyRead` veya `sandbox.credentials` ile kapatılır.
   - **Kilit (managed settings içinde):** `sandbox.enabled: true`, `sandbox.failIfUnavailable: true`, `sandbox.allowUnsandboxedCommands: false`. `sandbox.excludedCommands` boş bırakılır.
   - **Sınır:** Sandbox yalnızca shell komutlarını kapsar. Read, Edit, Write, WebFetch, WebSearch, MCP sunucuları ve hook'lar sandbox dışında çalışır. Bunlar 3. adımdaki PreToolUse hook'larıyla korunur.

**Kalan risk:**
- Harness dışından başlatılan süreçler (ör. kullanıcının agent'ın isteğiyle elle çalıştırdığı bir komut veya önceden kurulmuş bir arka plan süreci). Bunlar engellenmez; 4. adım ve hash zinciri ile tespit edilir.
- Harness'ın kendisindeki hatalar.

### 3.2 Harness güven seviyeleri

| Seviye | Koşul | Desteklenen mod |
|---|---|---|
| H0 | Hook yok veya hook'ları agent değiştirebilir | Düz iş birlikçi (`unobserved`) |
| H1 | Kilitlenebilir, engelleyebilen hook'lar | Sertleştirilmiş; ağ gözlemi yalnızca araç düzeyinde |
| H2 | H1 + kilitlenebilir ve proxy'lenebilir shell sandbox'ı | Sertleştirilmiş, tam |

Claude Code, 2026-10-16 belgelerine göre H2 koşullarını karşılar. Diğer harness'ların seviyesi belirlenmelidir (§10).

### 3.3 Yerel güven sınırı: sistem kullanıcısı ve admin hesapları

Sertleştirilmiş mod şu varsayıma dayanır: agent kullanıcının hesabıyla çalışır, ama root'a veya başka bir kullanıcıya ait dosyaları değiştiremez. Bu varsayım iki yerden delinebilir.

**Açık 1: Admin hesap.** macOS'ta geliştirici hesabı genelde admin'dir.
- **sudo parola önbelleği:** sudo, parola girildikten sonra varsayılan olarak 5 dakika boyunca tekrar sormaz (`timestamp_timeout`). Bu sürede agent'ın Bash komutu root'a ait dosyaları değiştirebilir. Önbelleğin terminale mi süreç ağacına mı bağlı olduğu yapılandırmaya göre değişir. Claude Code'un Bash komutlarının bu önbelleği kullanıp kullanamadığı test edilmelidir (§10).
- **Parolasız sudo (`NOPASSWD`):** Bu durumda sınır hiç yoktur.
- **Onay oltası:** Agent bir parola veya Touch ID istemi tetikler, kullanıcı da alışkanlıkla onaylar. Teknik olarak engellenemez.

**Açık 2: Kullanıcıya ait parçalar.** Yalnızca ayar dosyasını kilitlemek yetmez:
- Hook komutu kullanıcının yazabildiği bir yerdeyse (ör. `~/.cargo/bin`), agent ayara dokunmadan programı değiştirebilir.
- Daemon kullanıcının hesabıyla çalışıyorsa agent onu durdurup aynı soket adresinde her şeye izin veren sahte bir daemon başlatabilir.
- Nesne deposu kullanıcıya aitse agent ona doğrudan yazabilir.

**Önlemler**
1. **Daemon ayrı bir sistem kullanıcısıyla çalışır** (ör. `_lonca`). macOS'ta launchd, Linux'ta systemd ile başlatılır. Nesne deposu, op log ve imza anahtarı bu kullanıcıya aittir. Soket, kullanıcının yazamadığı bir dizinde durur.
2. **Karşılıklı kimlik doğrulama:** Daemon, bağlanan sürecin uid'sini doğrular. Hook programı ve CLI da karşı tarafın daemon kullanıcısı olduğunu doğrular. Sahte bir daemon bu kontrolü geçemez.
3. **Hook programı ve tüm üst dizinleri root'a aittir.** Sertleştirilmiş kurulum `cargo install` ile değil, bir paketle yapılır (macOS pkg, Linux paketi). Managed settings zaten admin kurulumu gerektirdiği için bu ek bir yük getirmez.
4. **sudo kontrolü:** Hook, her oturum başında kullanıcının hesabından `sudo -n true` çalıştırır. Komut parola sormadan başarılı olursa (önbellek açık veya `NOPASSWD`) oturum `unobserved` sayılır ve kullanıcı uyarılır. Önerilen ayar: `timestamp_timeout=0` ya da günlük işler için admin olmayan bir hesap.
5. **Bütünlük izlemesi:** Daemon, kendi kullanıcısıyla managed settings dosyasının, hook programının ve sudo yapılandırmasının hash'ini izler. Değişiklik olursa tüm oturumlar kirli sayılır ve alarm verilir. Böylece agent bir sınırı aşmayı başarsa bile bu fark edilir.
6. **Onay ekranını daemon üretir:** İnsan onayı istendiğinde gösterilen içerik (işlem, kapsam, isteyen oturum) agent'tan değil daemon'dan gelir. Kullanıcıya açık bir kural verilir: "Agent'ın senden istediği bir sistem istemini onaylama." Kullanıcı varlığı bir insanın dokunduğunu kanıtlar, neyi onayladığını kanıtlamaz.

**Kalan risk:** Admin bir kullanıcı agent'ın isteğiyle parolasını bilerek girerse bu engellenemez; yalnızca 5. önlemle tespit edilir. Bu, işletim sistemi düzeyinde bir sınırdır ve bizim katmanımızda çözülemez.

## 4. Mimari

```
  Agent'lar (MCP/CLI)          İnsan (CLI + kullanıcı varlığı)
  ayrı çalışma alanları                          │
          │                                      │
          └───────── istek: Unix soket ──────────┘
                             │
  ┌──────────────────────────▼───────────────────────────┐
  │ Gatekeeper daemon — tek yazıcı                       │
  │ oturum/capability · Cedar · lease · merge queue      │
  │ köken takibi · karar fonksiyonu (saf)                │
  └──────┬────────────────────────────────────┬──────────┘
         │ iş ↓  ↑ imzalı attestation         │ onaylı işlem
  ┌──────▼────────────────┐   ┌───────────────▼──────────┐
  │ Kanıt üreticileri     │   │ Çekirdek                 │
  │ sandbox build/test,   │   │ Git nesne deposu         │
  │ kapsam, beyan–diff    │   │ refs/lonca/oplog (zincir)  │
  │ (deterministik değil) │   │ refs/lonca/policy          │
  └───────────────────────┘   └───────────────┬──────────┘
                                              │ Git köprüsü
                              ┌───────────────▼──────────┐
                              │ Uzak depo (GitHub)       │
                              │ log başı çapası          │
                              └──────────────────────────┘

  Yan süreçler:
  AI Danışman (yetkisiz) ── öneri ──▶ Gatekeeper
  Auditor (ayrı binary, CI'da da) ── salt okunur ──▶ çekirdek + uzak depo
```

## 5. Bileşenler

### 5.1 Çekirdek ve Git uyumu

- **İçerik:** Git blob/tree/commit nesneleri, Git ile birebir uyumludur.
- **Değişiklik kimliği:** Commit hash'i rebase ve merge queue'da değişir. Bu yüzden her değişikliğin sabit bir `change-id`'si vardır (jj modeli). Lease, beyan ve attestation bu kimliğe bağlanır.
- **Meta veri:** Op log, attestation, capability, lease ve politika kayıtları Git nesneleri olarak `refs/lonca/*` altında durur. Push edildiğinde uzak depoya taşınır.
- **Köprü:**
  - `lonca git push` yalnızca trunk'ı ve `refs/lonca/*`'ı gönderir; agent çalışma alanları yerel kalır.
  - `lonca git pull` ile dışarıdan gelen commit'ler `import.external` işlemi olarak log'a girer, köken etiketi `unverified` olur.
- **Düz `git` ile yapılan yerel değişiklik:** Daemon ref değişimini algılar, `import.unmediated` olarak kaydeder ve işaretler. Politika bunu reddedip geri alabilir.
- **Push edilmiş geçmiş:** Undo yeni commit üretir. Force push varsayılan olarak kapalıdır.
- **Saflık:** Çekirdek saf fonksiyonlardan oluşur; aynı girdi her makinede aynı hash'i üretir. Ağ, AI veya rastgelelik bağımlılığı yoktur.

### 5.2 Operation Log

- Commit'lerin ötesinde **her işlem** kaydedilir: öneri, entegrasyon, revert, yetki verme/alma, lease alma/bırakma, politika değişikliği, redaction, içe aktarma.
- Log sadece eklemeye açıktır (append-only); her kayıt bir öncekinin hash'ini içerir (hash zinciri).
- **Zaman:** Daemon her kayda zaman damgası atar. Süre dolumu ve hız kuralları ("5 dakikada 3 revert") bu kayıtlı zamanla değerlendirilir. Yeniden oynatmada aynı zaman kullanıldığı için karar deterministik kalır. Zaman zincir boyunca azalmaz.
- **Girdiler:** Her kayıt, kararın tüm girdilerinin hash'lerini taşır: istek, capability, politika sürümü, attestation'lar, trunk durumu.
- **İmza:** Tüm kayıtları daemon imzalar. İnsan kaynaklı kayıtlar ek olarak insanın kullanıcı varlığı gerektiren imzasını taşır (§5.4).
- **Çapa:** Log başının hash'i her push'ta uzak depoya gider. Yerelde geçmiş yeniden yazılırsa bir sonraki karşılaştırmada ortaya çıkar. İsteğe bağlı olarak ikinci bir tanık (ayrı repo veya şeffaflık günlüğü) kullanılabilir.
- **Saklama:** Log'un referans verdiği nesneler GC ile silinmez, çünkü undo bunlara ihtiyaç duyar.
- **Atomiklik:** Daemon tek yazıcıdır. Lease edinme ve token rotasyonu gibi durum değişiklikleri sıralı ve atomik olarak uygulanır.

### 5.3 Undo, revert ve redaction

- Undo log'u hiçbir zaman değiştirmez. **Telafi edici yeni bir işlem** üretir ve bu işlem de Gatekeeper'dan geçer.
  - `lonca op undo <op-id>`
  - `lonca op revert --actor agent:x --since 2026-10-15T14:00` önce bir telafi planı çıkarır (varsayılan olarak dry-run) ve insan onayı ister.
- **`change.integrate` geri alma:** Üstüne kurulu değişiklik varsa yapısal revert yapılır. Çakışma çıkarsa çakışma merdivenine düşer (§6).
- **`cap.grant` geri alma:** Yetki iptal edilir. O yetkiyle yapılmış işlemler otomatik geri alınmaz. `lonca op revert --cap cap_x` bu işlemleri listeler ve telafi önerisi üretir.
- **Redaction:** Sızan bir sır veya kişisel veri için `blob.redact` kullanılır. İçerik silinir; hash ve bir tombstone kalır. İnsan imzası gerektirir. Push edilmiş geçmişte bu işlem uzak tarafta geçmişin yeniden yazılmasını gerektirir (açık soru).

### 5.4 Kimlik, oturum ve imza

- **Aktör kimlikleri:** `human:ayse`, `agent:refactor-bot/session-81f2`. Agent kimliği model, sürüm, oturum ve onu başlatan görevi içerir.
- **Yetki zinciri:** Her işlem tam yetki zincirini taşır: `human:ayse → task:T-142 → agent:X (session)`.
- **Oturum:**
  - İnsan, oturumu `lonca session start --task T-142 --cap <şablon>` ile başlatır. Bu, MCP üzerinden insan onayıyla da yapılabilir.
  - Daemon oturuma kısa ömürlü bir token verir. Token Unix soket üzerinden kullanılır; daemon ayrıca peer credential'larla (uid/pid) oturumu doğrular. Hook'lar ve CLI da karşı tarafın daemon kullanıcısı olduğunu doğrular (§3.3).
- **Agent'ların uzun ömürlü anahtarı yoktur.** Agent işlemlerini daemon imzalar. İmzanın anlamı şudur: "S oturumu, C yetkisiyle bunu istedi ve şu karar verildi."
- **İnsan imzası kullanıcı varlığı ister:** macOS'ta Secure Enclave + Touch ID, diğer sistemlerde FIDO2 güvenlik anahtarı kullanılır. Agent bu dokunuşu üretemez. Diskte duran bir SSH/GPG anahtarını ise agent da kullanabilir. Bu yüzden politika değişikliği ve onay gibi işlemler için bu tür anahtarlar kabul edilmez. Onay isteminin içeriğini agent değil daemon üretir (§3.3).
- **Alt-agent'lar:** Bir agent kendi capability'sini yalnızca daraltarak alt oturumuna devredebilir (ilke 6). Devir log'a yazılır.
- **Zincirleme iptal "her şey" demektir.** Bir insanın veya oturumun yetkisi alındığında ondan türeyen her şey düşer: capability'ler, lease'ler, bekleyen öneriler, kuyruktaki doğrulama işleri, müzakere katılımları ve oturum token'ları.

### 5.5 Capability'ler

- Biscuit benzeri token'lar kullanılır: yalnızca daraltılabilir (attenuation-only), çevrimdışı doğrulanabilir ve Datalog ile ifade edilir.
- **Kapsam:** yol, sembol, işlem tipleri, boyut sınırı (dosya/satır) ve süre.
- **Varsayılan red:** İşlem tipleri sabit bir enum'dur. Bilinmeyen tip, oluşturma anında reddedilir. Hiçbir zaman "X dışındaki her şey" biçiminde kural yazılmaz.
- **Agent'a asla verilemeyen işlemler** (politika ile de açılamaz): yetki yaratma/genişletme, `policy.update`, `blob.redact`, op log ve Auditor ayarları, başkasının oturumunu yönetme.
- Süre dolumu, log'daki işlem zamanıyla karşılaştırılır.
- Görev kapandığında capability otomatik düşer.

### 5.6 Policy Engine

- **Dil:** Cedar önerilir. Değerlendirmesi deterministik ve yan etkisizdir; politikalar statik olarak analiz edilebilir.
- **Konum:** Politika kod branch'lerinde değil, korumalı `refs/lonca/policy` ref'inde durur. Bu sayede gevşek politikalı bir branch merge edilerek kurallar zayıflatılamaz. Değerlendirme her zaman bu ref'in log'da kayıtlı sürümüyle yapılır.
- **Değişiklik:** Politikayı değiştirmek insanın kullanıcı varlığı imzasını gerektirir. Kritik kurallar için iki imza gerekir. Tek geliştirici için iki imzanın yerine "imza + bekleme süresi" seçeneği vardır (ör. 1 saat; bu sürede değişiklik iptal edilebilir).
- **AI taslağı:** AI doğal dilden politika *taslağı* üretebilir. Taslak Cedar'a derlenir, statik analizle "bu değişiklik hangi yetkileri genişletiyor" farkı çıkarılır ve insan onayına sunulur.

Örnek kurallar:

- Agent'lar `migrations/` altında dosya silemez.
- Aynı sembole 5 dakikada 3'ten fazla revert yapılırsa dur ve insana eskale et.
- `auth/` altına dokunan değişiklik 2 insan onayı ister.
- Tek bir agent oturumu en fazla N dosya / M satır değiştirebilir (blast radius).
- `import.unmediated` işlemi reddedilir ve geri alınır.
- Kirli bir oturumun önerisi yalnızca insan onayıyla entegre edilebilir.

### 5.7 Lease Manager (sembol kiralama)

Agent'lar dosya değil **sembol** (fonksiyon, sınıf, metod) düzeyinde kiralama alır. Sembol çıkarımı tree-sitter ile yapılır.

| Tür | Kapsam | Sahiplik |
|---|---|---|
| `edit` | Bir sembolün gövdesi | Tek sahip |
| `insert` | Bir kapsayıcıya (dosya, sınıf) yeni üye ekleme | Çok sahip olabilir. Eklemeler deterministik sırayla (lease sırası) birleştirilir. |
| `imports` | Dosya başındaki import/using bloğuna ekleme | Kiralama gerekmez; küme olarak birleştirilir. Silme `edit` gerektirir. |
| `rename` / `delete` | Sembol ve bilinen referansları | Geniş kapsam; politika onayı gerektirebilir |

- **Edinme beklemesiz ve hepsi-ya-hiçtir.** Talep edilen kümenin bir parçası bile başkasında tutuluyorsa hiçbiri verilmez. Yanıtta sahip, niyeti ve bitiş zamanı döner. Bekleyerek kilit tutma olmadığı için deadlock oluşmaz. Agent bekleyebilir, müzakere açabilir veya başka işe geçebilir.
- **Süre:** Kiralama süreli ve yenilenebilirdir. Sahibi düşerse (heartbeat kesilirse) serbest kalır.
- **Görünürlük:** Herkes tüm kiralamaları ve niyetleri görebilir ("agent:Y bu hatayı çözüyor").
- **İmza değişikliği:** Bir sembolün dışa açık imzası değişirse (parametreler, dönüş tipi, görünürlük; tree-sitter ile tespit edilir) değişiklik genişletilmiş doğrulamaya düşer. Bilinen çağıranların lease sahiplerine bildirim gider ve merge queue'da tam test koşulur. Kesin çağıran analizi (LSP veya derleyici) sonraki fazdadır.

### 5.8 Merge Queue

- Trunk'a girişin **tek yolu** merge queue'dur.
- Her değişiklik, kuyruk başındaki trunk durumuna yapısal olarak rebase edilir. Doğrulama **bu birleşmiş durum üzerinde** koşar ve kanıt birleşmiş durumun tree hash'ine bağlanır.
- **Neden gerekli:** Farklı semboller üzerinde çalışan iki doğru değişiklik birlikte yanlış olabilir. Örneğin A, `f`'nin davranışını değiştirir; B, `f`'yi kullanan `g`'yi yazar. Lease bunu önlemez. Yalnızca birleşmiş durumda yapılan doğrulama yakalar (testler kapsıyorsa).
- **Verim:** 20 agent'lık yükte spekülatif toplu doğrulama yapılır. Toplu doğrulama başarısız olursa grup ikiye bölünerek suçlu değişiklik bulunur.

### 5.9 Verification Pipeline (halüsinasyon savunması)

Kanıt üreticileri her değişiklik için şu kontrolleri **kendileri** yapar. Her kontrol imzalı bir attestation üretir.

1. **Sözdizimi/AST geçerliliği.**
2. **Kapsam:** Gerçek diff'ten hesaplanan semboller, lease ile capability'nin kesişimi içinde mi?
3. **Beyan–diff tutarlılığı:** Agent'ın *yapısal* beyanı (düzenlenen, eklenen ve silinen semboller, silinen dosyalar, imza ve test değişiklikleri) hesaplanan gerçek etkiyle birebir karşılaştırılır. Uyumsuzluk varsa öneri reddedilir. Serbest metin `intent` yalnızca insanlar içindir; karar girdisi değildir. Böylece bu kontrol AI gerektirmez.
4. **Build:** Sandbox'ta yapılır. Ağ yoktur, sır yoktur, depo salt okunurdur; süre ve bellek sınırı vardır.
5. **Testler:** Aynı sandbox'ta koşulur. Agent'ın raporu yok sayılır.
6. **Test bütünlüğü:**
   - Test sayısı düşmemelidir. Silinen, atlanan veya `Skip`/`Ignore` eklenen testler eskalasyona düşer.
   - Mevcut testleri değiştiren bir öneride, temel (base) test paketi yeni koda karşı da koşulur.

**Flaky testler:** Tekrar sayısını politika belirler; tüm denemeler kanıta yazılır.

**Karar:** Karar fonksiyonu yalnızca attestation'ları okur. Build ve test sonucu *kanıttır*, kararın kendisi değildir.

**Doğrulama-kritik yollar:** Gatekeeper agent'ın kodunu build ederken çalıştırır (MSBuild target'ları, npm script'leri, `build.rs`). Bu yüzden şu yollar politika dosyaları kadar hassastır:
- build script'leri ve proje dosyaları,
- CI tanımları (`.github/workflows` vb.),
- lockfile'lar,
- `.lonca/`.

Agent'ın bunlara yazması ayrı bir capability ve insan onayı ister. Yeni test eklemek serbesttir; mevcut testi değiştirmek veya silmek madde 6'ya tabidir.

**Sandbox sınırı:** Sandbox içinde agent'ın yazdığı kod çalışır. Daemon'un imza anahtarı ve log'a yazma yetkisi sandbox'ın erişemeyeceği yerdedir.

**Maliyet:** Oturum başına ve global bir doğrulama kotası (CPU-dakika/saat) vardır. Kota aşılınca yeni öneri kabul edilmez. Aynı tree için doğrulama tekrarlanmaz; sonuç önbellekten gelir.

### 5.10 Köken (provenance) ve taint (prompt injection savunması)

Kirlilik hem **oturumda** hem **içerikte** taşınır.

**Oturum ne zaman kirlenir:** Dış içerik okunduğunda. Gözlem modelin beyanından değil, şu kaynaklardan gelir:
- **Ağ proxy'si:** İzole modda sandbox'ın, sertleştirilmiş modda harness sandbox'ının tek ağ çıkışı daemon'un proxy'sidir. Her dış istek kaydedilir ve oturumu kirletir.
- **Harness entegrasyonu:** Agent çalıştırıcısının hook'ları (ör. Claude Code `PreToolUse`) web okuma, issue okuma ve dosya okuma gibi araç çağrılarını daemon'a bildirir ve gerektiğinde engeller. Harness modelden daha güvenilirdir.
  - Düz iş birlikçi modda hook'lar atlatılabilir.
  - Sertleştirilmiş modda hook'lar kilitlidir ve gözlem kesilirse oturum kirli sayılır (§3.1).
- **Güvenilmeyen repo yolları:** Politikada "güvenilmeyen" işaretli yolların (ör. `vendor/`, `third_party/`, içe aktarılmış issue metinleri) okunması.

**İçerik etiketi:**
- Kirli bir oturumun ürettiği değişiklik `provenance: tainted` taşır.
- İnsan inceleyip onaylayınca etiket `reviewed` olur; artık okunması kimseyi kirletmez.
- Onaylanmamış kirli içeriği okuyan oturum kirlenir.

**Müzakere mesajları** göndericinin etiketini taşır. Kirli bir mesajı okuyan oturum da kirlenir.

**Kirli oturum** şunları yapamaz:
- hassas yollara yazmak,
- yetki talep etmek,
- doğrudan entegrasyon yapmak (yalnızca draft üretebilir; entegrasyon insan onayına düşer).

**Kalıcılık:** Kirlilik oturum boyunca kalıcıdır; temizlenemez, yeni oturum gerekir.

**Kör nokta:** Repoda zaten bulunan düşmanca metnin (yorumlar, README) tam bir çözümü yoktur. Danışman katmanı bunları işaretleyebilir.

### 5.11 Agent arayüzü (MCP + CLI)

- Daemon'un iki ön yüzü vardır: **MCP sunucusu** (agent'lar için) ve **CLI** (insanlar ve script'ler için). İkisi aynı işlemleri sunar.
- **Araçlar:** `status`, `lease.acquire/release/list`, `change.propose` (yapısal beyanla), `change.status` (kuyruk durumu ve kanıtlar), `negotiate.*`, `history.query`, `cap.request` (insan onayına düşer).
- **Hata yanıtları** makine tarafından okunabilir ve eyleme dönüktür. Örnek: `lease_held: holder=agent:Y, intent="...", expires_at=...`.
- MCP yalnızca taşıma katmanıdır. Yetki token'dan gelir; araç açıklamaları güvenlik sınırı değildir.

### 5.12 Agent müzakeresi (Basamak 2)

- Mesajlar agent'lar arasında doğrudan değil, daemon üzerinden gider ve log'a yazılır.
- **Yapısal mesaj türleri:** `claim`, `propose_split`, `yield`, `counter`, `accept`.
- **Sınırlar:** tur sayısı (ör. 4) ve süre. Aşılırsa Basamak 3'e geçilir.
- **Çıktı** her zaman ya bir lease devri ya da bir değişiklik önerisidir. İkisi de Gatekeeper'dan geçer.

### 5.13 Bağımsız Denetçi (Auditor)

- Ayrı bir binary'dir; salt okunur çalışır.
- **Yeniden oynatma:** Log'daki her işlem için karar fonksiyonunu kayıtlı girdilerle yeniden çalıştırır ve sonucun kayıtlı kararla aynı olduğunu doğrular.
- **Kontroller:** hash zinciri, imzalar, zamanın azalmaması, attestation imzaları ve yerel log başının uzak çapayla karşılaştırması.
- **Ne zaman çalışır:**
  - daemon'dan bağımsız olarak periyodik (launchd/cron),
  - push öncesinde,
  - CI'da, push edilmiş `refs/lonca/*` üzerinde. CI koşusu gerçekten ayrı bir altyapıdır.
- **Uyumsuzlukta:** Alarm verir ve repoyu salt-okunur moda geçirir. Auditor'ın tek yazma yetkisi bu dondurma bayrağıdır.
- AI içermez.

### 5.14 AI Danışman katmanı

Yetkisizdir; yalnızca öneri ve işaret üretir:

- Değişiklikleri niyet ve riske göre özetlemek.
- Çakışma çözümü önermek.
- Anormal agent davranışını işaretlemek (alakasız dosyalara yönelme, ani kapsam büyümesi).
- Şüpheli yetki taleplerini işaretlemek (talep, kirli içerik okunduktan hemen sonra mı geldi?).
- Geçmişte doğal dil sorgusu ("yuvarlama hatası ne zaman ve neden girdi?").

Ek kurallar:

- Danışman da dış içerik okur; çıktıları köken etiketi taşır.
- LLM çağrıları için oturum başına ve günlük global bir tavan vardır. Tavan, çağrıdan önce atomik olarak ayrılır.
- Kodun dışarı çıkmaması gereken senaryolar için yerel model seçeneği sunulur.

## 6. Çakışma Çözüm Merdiveni

| Basamak | Mekanizma | Deterministik mi? | Sonuç nereden geçer |
|---|---|---|---|
| 0 | Sembol kiralama (beklemesiz, hepsi-ya-hiç) | Evet | — |
| 1 | Yapısal (AST tabanlı) 3-yollu merge | Evet | Merge queue + Verification |
| 2 | Agent'lar arası müzakere (sınırlı tur ve süre) | Hayır | Gatekeeper + Merge queue |
| 3 | Önceden tanımlı politika (kod sahibi, eski lease önceliği vb.) | Evet | Policy Engine |
| 4 | İnsan kararı | — | İmzalı işlem |

Kural: Bir basamak başarısız olursa veya zaman aşımına uğrarsa bir sonrakine geçilir. Basamak 2'nin çıktısı **asla** doğrulamasız birleşmez.

## 7. Veri Modeli (taslak)

```yaml
# Değişiklik = Git commit + ek başlıklar (içerik Git ile birebir uyumlu)
commit:
  tree: <git sha>
  parents: [<git sha>]
  author: ...                      # insan okunur; yetki kaynağı DEĞİL
  change-id: chg_k3x9...           # rebase ve merge queue'da sabit kalır
  lonca-session: agent:ratelimit-bot/session-81f2
```

```yaml
# Yapısal beyan — agent yazar; karar girdisidir
claim:
  change: chg_k3x9
  intent: "Ödeme servisine rate limiting ekle"   # yalnızca insanlar için
  edits:   [src/billing/client.ts#BillingClient.charge]
  adds:    [src/billing/client.ts#BillingClient.throttle]
  deletes: []
  deleted_files: []
  signature_changes: []
  test_changes: { added: 3, modified: 0, deleted: 0 }
```

```yaml
# Attestation — kanıt üreticisi üretir; imzalı
attestation:
  subject: { change: chg_k3x9, tree: <birleşmiş durumun tree sha'sı> }
  check: tests        # syntax | scope | claim_diff | build | tests | test_integrity
  result: pass
  details: { count: 412, attempts: 1 }
  env: sha256:...     # sandbox imajı + araç sürümleri
  log: <blob sha>
  producer: verifier/sandbox-v1
  signature: ed25519:...
```

```yaml
# İşlem kaydı
operation:
  seq: 18342
  prev_hash: sha256:...
  time: 2026-10-16T14:03:12.481Z   # daemon atar; karar girdisidir
  type: change.propose | change.integrate | op.revert | cap.grant | cap.revoke
      | lease.acquire | lease.release | policy.update | blob.redact
      | import.external | import.unmediated
  actor: agent:ratelimit-bot/session-81f2
  delegation: [human:ayse, task:T-142, agent:ratelimit-bot/session-81f2]
  request: <blob sha>
  inputs:
    capability: cap_7f3a
    policy: <refs/lonca/policy commit sha>
    attestations: [<sha>, ...]
    state: <trunk sha>
  decision: allow | deny | escalate
  reason: "lease_missing: BillingClient.refund"
  human_signature: fido2:...        # yalnızca insan kaynaklı işlemlerde
  signature: ed25519:...            # daemon
```

```yaml
# Capability (Biscuit token'ının mantıksal içeriği)
capability:
  id: cap_7f3a
  holder: agent:ratelimit-bot/session-81f2
  issued_by: human:ayse
  scope:
    paths: ["src/billing/**"]
    symbols: ["BillingClient.*"]
    ops: [change.propose, lease.acquire]   # sabit enum; bilinmeyen = red
    max_lines: 300
  expires_at: 2026-10-15T20:00:00+03:00
  parent: cap_1a22        # yalnızca daraltabilir
```

```yaml
# Lease
lease:
  id: lse_19c0
  set: lset_44a1          # hepsi-ya-hiç edinilen küme
  type: edit              # edit | insert | rename | delete
  symbol: src/billing/client.ts#BillingClient.charge
  holder: agent:ratelimit-bot/session-81f2
  intent: "rate limiting"
  expires_at: 2026-10-15T18:45:00+03:00
```

## 8. Uygulama Fazları

**Faz 0 — Netleştirme**
- Uygulama dili (Rust) ve proje adı (Lonca) seçildi. Lisans seçilir.
- `change-id` formatı belirlenir.
- Tehdit modeli onaylanır.

**Faz 1 — Güvenli temel**
- Git formatlı nesne deposu ve daemon (tek yazıcı; baştan ayrı bir sistem kullanıcısıyla çalışabilecek şekilde tasarlanır).
- Operation Log: hash zinciri, imza, kayıtlı zaman, uzak çapa.
- Oturumlar, yetki zinciri, capability'ler.
- CLI + MCP iskeleti.
- Undo ve telafi edici işlemler.
- Git köprüsü (push/pull, `import.*`).
- Minimal Auditor: zincir, imza ve karar yeniden oynatma.

*Bitti sayılması için:* Bir agent oturumu yetkisi dahilinde değişiklik önerebilmeli; yetki dışı işlem reddedilip log'a yazılmalı; log GitHub'a push edilip CI'da Auditor'dan geçmeli.

**Faz 2 — Eşzamanlılık**
- Tree-sitter ile sembol çıkarımı (önce tek dil).
- Lease Manager.
- Kapsam kontrolü.
- Yapısal merge (Basamak 1).
- Merge queue: önce seri, sonra toplu.

*Bitti sayılması için:* 20 agent'ın aynı dosyada farklı fonksiyonlar üzerinde çalıştığı bir demo senaryosunda kayıp güncelleme sıfır olmalı ve trunk'a giren her durum doğrulanmış olmalı.

**Faz 3 — Doğrulama ve savunma**
- Sandbox, attestation'lar.
- Beyan–diff tutarlılığı, test bütünlüğü.
- Cedar politika ve imzalı politika değişikliği.
- Köken takibi (harness hook'ları + proxy).
- Sertleştirilmiş iş birlikçi mod: kurulum paketi (sistem kullanıcısı, root'a ait hook programı, managed settings), sudo kontrolü, bütünlük izlemesi, Claude Code profili.
- İzole mod.

**Faz 4 — Müzakere ve AI**
- Agent müzakere protokolü (Basamak 2).
- AI Danışman katmanı.
- İkinci dil desteği.
- Ekip sunucusu tasarımı.

## 9. Önceki Çalışmalar

Lisansları kullanmadan önce kontrol edilmeli.

- **Jujutsu (jj):** Git backend'li VCS; operation log, `op undo` ve sabit change-id fikirleri.
- **Mergiraf:** Tree-sitter tabanlı yapısal merge (Basamak 1).
- **gitoxide:** Saf Rust Git uygulaması.
- **tree-sitter:** Sembol çıkarımı.
- **Pijul:** Patch teorisi; değişikliklerin sırasından bağımsız birleştirilmesi (`insert` lease sıralaması için ilham).
- **Biscuit:** Capability token'ları.
- **Cedar:** Politika dili.
- **Sigstore / in-toto / SLSA:** İmza ve kanıt attestation formatları.
- **bors, GitHub merge queue:** Merge queue modeli.

## 10. Açık Sorular

- **Temel:** jj-lib üzerine mi kurulacak, yoksa gitoxide ile kendi çekirdeğimiz mi yazılacak?
- **Lisans:** Apache-2.0 veya MIT öneriliyor.
- **Marka:** "Lonca" için TÜRKPATENT ve EUIPO'da marka araması yapılmalı.
- **Dil desteği:** Sembol desteği ilk hangi dil(ler) için verilecek?
- **change-id:** Commit başlığı olarak mı, trailer olarak mı tutulacak? GitHub'ın ek commit başlıklarını koruyup korumadığı doğrulanmalı.
- **Sembol kimliği:** Yeniden adlandırma ve taşıma sırasında nasıl stabil tutulacak?
- **Redaction:** Push edilmiş geçmişte nasıl uygulanacak?
- **Sandbox:** macOS'ta container mı, OS sandbox mı? Tekrarlanabilirlik nasıl sağlanacak (Nix, container imajı)?
- **Auditor:** Karar fonksiyonu kütüphanesini Gatekeeper ile paylaşacak mı? Paylaşırsa ortak hatalar yakalanmaz.
- **Tek geliştirici:** "İki insan imzası" yerine ne kullanılacak (imza + bekleme süresi yeterli mi)?
- **Ekip sunucusu:** Tek sıralayıcı modelinden sunucuya geçiş nasıl olacak?
- **Harness seviyeleri:** Codex, Cursor ve diğer agent çalıştırıcıları hangi güven seviyesinde (H0/H1/H2)?
- **Claude Code ayrıntıları:** `allowManagedHooksOnly`'nin tam etki listesi belgelerde doğrulanamadı; uygulamadan önce test edilmeli.
- **sudo önbelleği:** Claude Code'un Bash komutları kullanıcının sudo parola önbelleğini kullanabiliyor mu? Test edilmeli (§3.3).
- **Doküman dili:** Açık kaynak için İngilizce'ye çevrilmeli mi?

Faz 0'da kapananlar (gerekçeleri `docs/decisions.md`'de): temel **gitoxide + kendi çekirdeğimiz**, lisans **Apache-2.0**, change-id **jj ile birebir aynı `change-id` başlığı**, ilk diller **Rust, Python, TypeScript/TSX, JavaScript, C#, Go**, sandbox **macOS'ta Seatbelt, Linux'ta bubblewrap**.

## 11. Uygulama Durumu (v0.1, 2026-10-16)

| Bölüm | Durum | Not |
|---|---|---|
| §5.1 Çekirdek, Git uyumu, köprü | Tamam | Push/pull için `git` ikilisi; `ext::` vb. komut çalıştıran protokoller reddediliyor. |
| §5.2 Operation Log | Tamam | SHA-256 zincir, daemon imzası, kayıtlı zaman, `refs/lonca/oplog`, push ile çapa. |
| §5.3 Undo / revert / redaction | Tamam / kısmi | Undo ve revert telafi edici işlem; redaction mantıksal (blob daemon tarafından gizleniyor, Git geçmişinden silinmiyor). |
| §5.4 Kimlik, oturum, imza | Tamam | Token'ın yalnızca hash'i diskte; Secure Enclave imzacı (`lonca-se`); `require_presence`. |
| §5.5 Capability | Tamam, sapmalı | Biscuit yerine daemon tarafı kayıt; daraltma (`scope_within`) ve zincirleme iptal korunuyor. |
| §5.6 Policy Engine | Tamam | Cedar, hata = red; `@escalate`, `@approvals`; politika korumalı ref'te. Tek geliştirici için onay sayısı kayıtlı insan sayısına kısılıyor (`approvals_capped`); "imza + bekleme süresi" yapılmadı. |
| §5.7 Lease Manager | Tamam | Beklemesiz hepsi-ya-hiç; `edit` / `insert` / `rename`; import eklemeleri kiralamasız. İmza değişikliği tespit ediliyor ama çağıranlara bildirim yok. |
| §5.8 Merge Queue | Tamam (seri) | Kilit dışında merge + doğrulama; toplu (spekülatif) doğrulama yapılmadı. 20 agent / tek dosya testi 1 saniyenin altında geçiyor. |
| §5.9 Verification | Tamam / kısmi | Sözdizimi, build, test, beyan–diff, test silme/atlama eskalasyonu. Değişen testlerde eski test paketini yeni koda karşı koşmak yapılmadı. |
| §5.10 Köken / taint | Tamam | Hook gözlemleri, `unobserved` = kirli, gözlem–etki tutarlılığı, müzakerede yayılma, ağ proxy'si (lsof ile atıf). Kirliliği içerik düzeyinde taşıma (okunan kirli içerik) kısmen: değişikliklerin köken etiketi var, okuyanı kirletme yalnızca "güvenilmeyen yollar" üzerinden. |
| §5.11 MCP + CLI | Tamam | `lonca mcp` (9 araç), `lonca hook`, kapsamlı CLI. |
| §5.12 Müzakere | Tamam | Yapısal mesajlar, tur sınırı, `yield` ile kiralama devri. |
| §5.13 Auditor | Tamam | Karar, Facts ve merge yeniden hesaplama; yayımlanmış log karşılaştırması; dondurma bayrağı. Karar kodunu paylaşıyor (açık soru duruyor). |
| §5.14 AI Danışman | Tamam | `lonca advise`; günlük bütçe; diff kırpılmıyor, büyükse reddediliyor. Yalnızca sahte API'ye karşı test edildi. |
| §3.1–3.3 Sertleştirilmiş mod | Tamam, sahada denenmedi | Kurulum betikleri (macOS/Linux), peer uid kontrolü, sudo kontrolü, managed settings denetimi. Betikler `--render` ile ve Lonca'nın kendi denetleyicisiyle test edildi; gerçek `sudo` kurulumu çalıştırılmadı. |
| İzole mod | Yapılmadı | Container tabanlı agent çalıştırma. |
| Ekip sunucusu | Yapılmadı | Tasarım açık soru olarak duruyor. |

---

### CLAUDE.md için öneri

```markdown
## Proje bağlamı
Tasarım kaynağı: docs/design.md — her oturumda oku.
Değişmez kurallar:
- Çekirdek, Gatekeeper ve karar fonksiyonunda AI, ağ veya rastgelelik bağımlılığı yok.
- Karar fonksiyonu saf: tüm girdileri (zaman dahil) operation kaydında; kanıt ile karar ayrı.
- Tüm yazma işlemleri Gatekeeper'dan geçer; bypass eden kod yazma.
- Operation Log append-only; mevcut kayıtları değiştiren kod yazma. Undo = telafi edici işlem.
- Agent'lar uzun ömürlü anahtar tutmaz; agent işlemlerini daemon imzalar.
- Varsayılan red: bilinmeyen işlem tipi, kapsam veya yol reddedilir.
- Sertleştirilmiş modda daemon, hook programı ve depo kullanıcının yazabildiği yerlerde durmaz.
```
