# SecGuard — arxitektura va Google Play muvofiqligi

## 1. Umumiy sxema

```
┌──────────────────────────── ANDROID (Kotlin, Compose, MVVM) ────────────────────────────┐
│  UI (Compose)  ──►  MainViewModel (StateFlow)  ──►  ScanRepository                      │
│  ConsentScreen        │                              ├─ ApkStaticAnalyzer  (qurilmada)  │
│  HomeScreen           │                              ├─ UrlGuard           (qurilmada)  │
│                       │                              └─ ApiClient ─ HTTPS ──────────┐  │
│  PackageMonitorService (Foreground) ──► ScanRepository ──► Notifier (ogohlantirish)  │  │
│        ▲ dinamik BroadcastReceiver: ACTION_PACKAGE_ADDED                             │  │
│  BlacklistDb (SQLite) ◄── SyncRepository ◄── SyncWorker (6 soatda bir, WorkManager)  │  │
└───────────────────────────────────────────────────────────────────────────────────────┼──┘
                                                                                        ▼
┌────────────────────────── BACKEND (Python, FastAPI) ───────────────────────────────────┐
│  POST /v1/analyze/apk   → analyzer.py (libmagic + Androguard) → scoring.py             │
│  POST /v1/lookup/hash   → indicators (PostgreSQL)                                      │
│  POST /v1/url/check     → url_guard.py + indicators                                    │
│  GET  /v1/blacklist/sync?since=<ms>  → inkremental ro'yxat (active + revoked)          │
│  POST /v1/admin/indicators → qora ro'yxatni inson tekshiruvidan so'ng boshqarish        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

Asosiy qaror: **tekshiruv sukut bo'yicha qurilmada** bajariladi. Server — qora ro'yxat manbai va ixtiyoriy
(opt-in) chuqur tahlil. Ikki tomonda `RiskScoring.kt` ↔ `scoring.py` va `UrlGuard.kt` ↔ `url_guard.py` vaznlari bir xil.

## 2. Modul 1 — APK Static Analyzer

```
APK / o'rnatilgan ilova
  │
  ├─ [Python] libmagic MIME + zip tuzilmasi + zip-bomba limiti → AndroidManifest.xml bormi?
  ├─ SHA-256 (oqim bilan) ──► qora ro'yxat (sha256, cert)
  ├─ Manifest: uses-permission, service[permission=BIND_ACCESSIBILITY_SERVICE | BIND_NOTIFICATION_LISTENER_SERVICE],
  │            receiver[BIND_DEVICE_ADMIN], LAUNCHER activity bormi, debuggable, targetSdk
  ├─ Imzo: imzosiz? debug sertifikat? sertifikat SHA-256
  ├─ Zip: assets/*.apk|.dex (dropper), classes*.dex ichida "api.telegram.org/bot" (ma'lumot chiqarish izi)
  └─► RiskScoring.compute() ─► score 0-100 + sabablar ro'yxati
```

Ball: xavfli ruxsatlar vaznlari + signallar + kombinatsiyalar (SMS+internet, overlay+accessibility,
install+payload), yig'indi 100 bilan cheklanadi; Play'dan o'rnatilgan bo'lsa ×0.6; qora ro'yxat → 100.
Darajalar: 0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL.

Kodlar: `backend/analyzer.py`, `backend/scoring.py`, `android/.../core/ApkStaticAnalyzer.kt`, `core/RiskScoring.kt`.

## 3. Modul 2 — Telegram & Phishing Link Guard

```
URL matni (kiritilgan yoki Telegram "Ulashish" orqali)
  → normalizatsiya (sxema, host, port, userinfo)           [havola HECH QACHON ochilmaydi]
  → qora ro'yxat: host + ota-domenlar, t.me/<handle>
  → evristika: IP-host, '@', punycode, aralash alifbo, qisqartirgich, xavfli TLD, HTTP,
               brend taqlidi (leet + Levenshtein≤1), .apk havola, shubhali so'zlar, bot havolasi
  → ball 0-100 → SAFE <30 ≤ SUSPICIOUS <70 ≤ DANGEROUS + sabablar
```

Telegram chatlarini fonda o'qish YO'Q (bu Accessibility talab qilardi). Foydalanuvchi havola/faylni
Telegram'dagi **Ulashish → SecGuard** orqali yuboradi (`ACTION_SEND` intent-filter).

Kodlar: `backend/url_guard.py`, `android/.../core/UrlGuard.kt`.

## 4. Modul 3 — Lokal xavfsizlik monitori

```
Foydalanuvchi switch'ni yoqadi ─► POST_NOTIFICATIONS (13+) ─► startForegroundService
PackageMonitorService.onStartCommand
  ├─ startForeground(doimiy bildirishnoma, type=specialUse)
  └─ registerReceiver(ACTION_PACKAGE_ADDED, scheme=package)      // manifest orqali ishlamaydi (8+)
        onReceive → EXTRA_REPLACING emas → ScanRepository.scanInstalled(pkg)
              └─ score ≥ 30 → Notifier.showAlert: sabablar + "Ilova sozlamalari / o'chirish"
BootReceiver: qurilma yoqilganda foydalanuvchi yoqib qo'ygan bo'lsa qayta ishga tushiradi
```

## 5. Google Play muvofiqligi

| Talab | Qanday bajarilgan |
|---|---|
| Shaffoflik / Prominent Disclosure | `ConsentScreen`: vazifa, ma'lumotlar, ixtiyoriy bandlar, maxfiylik siyosati havolasi; rozilik versiyalanadi, bekor qilish va ma'lumotni o'chirish tugmasi bor |
| Ixtiyoriy ma'lumot yuborish | Server tekshiruvi (xesh, URL) va APK yuklash — alohida, sukut bo'yicha o'chiq checkbox'lar |
| Accessibility API | **Ishlatilmaydi.** Antivirus/xavfsizlik uchun u siyosat bo'yicha xavfli (rad etilish xavfi, qo'shimcha deklaratsiya). Arxitektura unga muhtoj emas: PACKAGE_ADDED + Share-intent yetarli |
| Fayl skanerlash | `MANAGE_EXTERNAL_STORAGE` yo'q. Faqat Storage Access Framework orqali foydalanuvchi tanlagan fayl va o'rnatilgan ilovalar. Boshqa fayllarga kirilmaydi |
| Maxfiy ma'lumot | SMS/kontakt/parol/karta o'qilmaydi; server APK'ni saqlamaydi (faqat xesh+natija) |
| Foreground service | `specialUse` + `FOREGROUND_SERVICE_SPECIAL_USE`; Play Console'da FGS deklaratsiyasi to'ldiriladi; doimiy bildirishnoma ko'rinadi |
| Paket ko'rinishi | `QUERY_ALL_PACKAGES` qo'shilmagan; `<queries>` launcher. Sideload (ikonkasiz) ilovalar ko'rinmasa, ruxsat deklaratsiya bilan qo'shiladi (manifestdagi izoh) |
| O'chirish | `REQUEST_DELETE_PACKAGES` kerak emas: ilova sozlamalariga yo'naltiriladi |
| Aldamchi da'volar | UI "100% himoya" demaydi; natija — ehtimoliy baho |

> Siyosatlar o'zgarib turadi: topshirishdan oldin Play Console'dagi joriy talablar (Data safety, FGS, `QUERY_ALL_PACKAGES`) va
> `targetSdk` talabini tekshiring.

## 6. Cheklovlar (ochiq aytilishi kerak)

1. **O'rnatishni to'xtatib bo'lmaydi.** Android bunga ruxsat bermaydi: monitor o'rnatishdan *keyin* darhol tekshiradi va ogohlantiradi.
2. Risk Score — evristika, hukm emas. SMS/dialer kabi qonuniy ilovalar ham yuqori ball olishi mumkin. Shuning uchun serverda avtomatik topilmalar `pending` bo'ladi va qora ro'yxatga faqat inson tasdiqlagach (`active`) o'tadi.
3. Havola ichidagi yakuniy manzil (qisqartirilgan havolalar) ochilmaydi, shuning uchun bunday havolalar faqat "ehtiyot bo'ling" belgisi oladi.
4. `API_KEY` APK ichidan chiqarib olinishi mumkin: production'da Play Integrity tekshiruvi, rate-limit va TLS pinning qo'shing.
5. Dex satrlarini qidirish oddiy bayt-qidiruv: obfuskatsiyalangan namunalarni o'tkazib yuborishi mumkin.

## 7. Ishga tushirish

Backend:
```bash
sudo apt install libmagic1
cd backend && pip install -r requirements.txt
export API_KEY=...  ADMIN_KEY=...  DATABASE_URL=postgresql+psycopg://user:pass@host/secguard
python3 test_core.py                 # tashqi kutubxonasiz testlar
uvicorn main:app --port 8000
# qora ro'yxatga yozuv qo'shish:
curl -X POST localhost:8000/v1/admin/indicators -H "X-Admin-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
     -d '{"kind":"domain","value":"evil.example","status":"active"}'
```
Android: `android/` papkasini Android Studio'da oching, `app/build.gradle.kts` dagi `API_BASE_URL`, `PRIVACY_POLICY_URL` ni o'zgartiring,
`~/.gradle/gradle.properties` ga `secguardApiKey=...` yozing, kutubxona versiyalarini yangilang, `./gradlew testDebugUnitTest`.
