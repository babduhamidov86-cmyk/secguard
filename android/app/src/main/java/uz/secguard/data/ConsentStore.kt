package uz.secguard.data

import android.content.Context

/**
 * Foydalanuvchi roziligi. Sukut bo'yicha hammasi o'chiq; server bilan har qanday
 * ma'lumot almashinuvi alohida va ixtiyoriy opt-in. Matn o'zgarsa VERSION oshiriladi va rozilik qayta so'raladi.
 */
class ConsentStore(context: Context) {
    private val p = context.applicationContext.getSharedPreferences("secguard_consent", Context.MODE_PRIVATE)

    val accepted: Boolean get() = p.getInt(K_VERSION, 0) == VERSION && p.getBoolean(K_ACCEPTED, false)
    val serverLookup: Boolean get() = accepted && p.getBoolean(K_SERVER, false)
    val apkUpload: Boolean get() = accepted && p.getBoolean(K_UPLOAD, false)
    var monitorEnabled: Boolean
        get() = accepted && p.getBoolean(K_MONITOR, false)
        set(v) { p.edit().putBoolean(K_MONITOR, v).apply() }

    fun accept(serverLookup: Boolean, apkUpload: Boolean) {
        p.edit().putInt(K_VERSION, VERSION).putBoolean(K_ACCEPTED, true)
            .putBoolean(K_SERVER, serverLookup).putBoolean(K_UPLOAD, apkUpload).apply()
    }

    /** Rozilikni bekor qilish: barcha ixtiyoriy funksiyalar o'chadi. */
    fun revokeAll() { p.edit().clear().apply() }

    private companion object {
        const val VERSION = 1
        const val K_VERSION = "version"; const val K_ACCEPTED = "accepted"
        const val K_SERVER = "server_lookup"; const val K_UPLOAD = "apk_upload"; const val K_MONITOR = "monitor"
    }
}
