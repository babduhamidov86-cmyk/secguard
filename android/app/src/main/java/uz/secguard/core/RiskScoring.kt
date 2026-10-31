package uz.secguard.core

/** Qora ro'yxat so'rovi interfeysi (SQLite yoki test uchun soxta ro'yxat). kind: sha256|domain|tg_handle|package|cert */
fun interface BlacklistLookup {
    fun contains(kind: String, value: String): Boolean
}

enum class RiskLevel { LOW, MEDIUM, HIGH, CRITICAL }

data class RiskReason(val code: String, val points: Int, val text: String)

data class Signals(
    val accessibilityService: Boolean = false,
    val deviceAdmin: Boolean = false,
    val notificationListener: Boolean = false,
    val telegramBotApi: Boolean = false,
    val embeddedPayload: Boolean = false,
    val unsigned: Boolean = false,
    val debugCert: Boolean = false,
    val noLauncher: Boolean = false,
    val debuggable: Boolean = false,
    val targetSdk: Int? = null,
    val installerPlay: Boolean = false,
    val hashBlacklisted: Boolean = false,
    val certBlacklisted: Boolean = false,
)

data class RiskReport(
    val packageName: String?,
    val appName: String?,
    val sha256: String?,
    val score: Int,
    val level: RiskLevel,
    val reasons: List<RiskReason>,
)

/**
 * Risk Score (0-100). Vaznlar backend `scoring.py` bilan BIR XIL bo'lishi shart:
 * server va qurilma bir xil ilovaga bir xil ball berishi uchun.
 */
object RiskScoring {
    const val ALERT_THRESHOLD = 30
    private const val PLAY_INSTALL_FACTOR = 0.6

    private val PERMISSION_WEIGHTS = mapOf(
        "READ_SMS" to 18, "RECEIVE_SMS" to 18, "SEND_SMS" to 15, "READ_CALL_LOG" to 10,
        "SYSTEM_ALERT_WINDOW" to 14, "REQUEST_INSTALL_PACKAGES" to 12, "RECORD_AUDIO" to 8,
        "READ_CONTACTS" to 6, "MANAGE_EXTERNAL_STORAGE" to 6, "DISABLE_KEYGUARD" to 6,
        "PACKAGE_USAGE_STATS" to 6, "QUERY_ALL_PACKAGES" to 5, "RECEIVE_BOOT_COMPLETED" to 4,
        "CALL_PHONE" to 4, "WRITE_SETTINGS" to 4, "READ_PHONE_STATE" to 3,
        "REQUEST_DELETE_PACKAGES" to 3, "CAMERA" to 3, "ACCESS_FINE_LOCATION" to 3,
    )

    fun shortName(permission: String) = permission.substringAfterLast('.').uppercase()

    fun levelFor(score: Int): RiskLevel = when {
        score >= 80 -> RiskLevel.CRITICAL
        score >= 60 -> RiskLevel.HIGH
        score >= 30 -> RiskLevel.MEDIUM
        else -> RiskLevel.LOW
    }

    fun compute(permissions: Collection<String>, s: Signals): Pair<Int, List<RiskReason>> {
        if (s.hashBlacklisted || s.certBlacklisted) {
            val why = if (s.hashBlacklisted) "SHA-256 qora ro'yxatda" else "Imzo sertifikati qora ro'yxatda"
            return 100 to listOf(RiskReason("blacklisted", 100, why))
        }
        val perms = permissions.map(::shortName).toSet()
        val reasons = mutableListOf<RiskReason>()

        for (name in perms.sorted()) {
            PERMISSION_WEIGHTS[name]?.let { reasons += RiskReason("perm:$name", it, "Xavfli ruxsat: $name") }
        }
        fun sig(active: Boolean, key: String, w: Int, text: String) {
            if (active) reasons += RiskReason("sig:$key", w, text)
        }
        sig(s.accessibilityService, "accessibility_service", 22, "Accessibility xizmati e'lon qilingan")
        sig(s.deviceAdmin, "device_admin", 20, "Device Admin qabul qiluvchisi e'lon qilingan")
        sig(s.notificationListener, "notification_listener", 14, "Bildirishnomalarni o'qish xizmati (OTP o'g'irlash xavfi)")
        sig(s.telegramBotApi, "telegram_bot_api", 20, "Kod ichida Telegram Bot API manzili bor (ma'lumot yuborish ehtimoli)")
        sig(s.embeddedPayload, "embedded_payload", 12, "Ilova ichida yashirin .apk/.dex fayl bor")
        sig(s.unsigned, "unsigned", 12, "Ilova imzolanmagan")
        sig(s.debugCert, "debug_cert", 10, "Debug sertifikati bilan imzolangan")
        sig(s.noLauncher, "no_launcher", 8, "Ishga tushirish ikonkasi yo'q (yashirin ilova)")
        sig(s.targetSdk != null && s.targetSdk < 23, "low_target_sdk", 6, "Eski targetSdk (<23): ruxsatlar so'ralmasdan beriladi")
        sig(s.debuggable, "debuggable", 5, "debuggable=true")

        val sms = perms.any { it == "READ_SMS" || it == "RECEIVE_SMS" }
        fun combo(active: Boolean, code: String, w: Int, text: String) {
            if (active) reasons += RiskReason("combo:$code", w, text)
        }
        combo(sms && "INTERNET" in perms, "sms_exfil", 10, "SMS o'qish + internet: SMS/OTP uzatish xavfi")
        combo("SYSTEM_ALERT_WINDOW" in perms && s.accessibilityService, "overlay_banker", 15,
            "Overlay + Accessibility: soxta oyna orqali ma'lumot o'g'irlash namunasi")
        combo("REQUEST_INSTALL_PACKAGES" in perms && s.embeddedPayload, "dropper", 15,
            "O'rnatish ruxsati + yashirin payload: dropper namunasi")
        combo(sms && "RECEIVE_BOOT_COMPLETED" in perms, "sms_persistent", 6,
            "SMS + qurilma yoqilganda avto-ishga tushish")

        var raw = reasons.sumOf { it.points }
        if (s.installerPlay) raw = (raw * PLAY_INSTALL_FACTOR).toInt()
        return raw.coerceIn(0, 100) to reasons.sortedByDescending { it.points }
    }
}
