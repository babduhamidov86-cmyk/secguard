package uz.secguard.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.net.Uri
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

class InvalidApkException(message: String) : Exception(message)

/** Vaqtincha nusxa (cache) va uning xeshi. Chaqiruvchi tahlildan keyin `file.delete()` qilishi shart. */
class StagedApk(val file: File, val sha256: String)

/**
 * APK / o'rnatilgan ilovani QURILMANING O'ZIDA statik tahlil qiladi.
 * Hech narsa ishga tushirilmaydi; faqat PackageManager metama'lumoti va zip tuzilmasi o'qiladi.
 */
class ApkStaticAnalyzer(context: Context, private val blacklist: BlacklistLookup) {
    private val appContext = context.applicationContext
    private val pm: PackageManager = appContext.packageManager

    // ---------- Kirish nuqtalari ----------
    /** Yangi o'rnatilgan ilova (PACKAGE_ADDED). NameNotFoundException: paket ko'rinmasa. */
    suspend fun analyzeInstalled(packageName: String): RiskReport = withContext(Dispatchers.IO) {
        val info = installedInfo(packageName)
        val path = info.applicationInfo?.sourceDir
        val sha = path?.let { runCatching { sha256Of(File(it)) }.getOrNull() }
        buildReport(info, path, sha, installed = true)
    }

    /** Foydalanuvchi tanlagan / ulashgan APK (SAF yoki ACTION_SEND URI). Blocking: IO oqimida chaqiring. */
    fun stage(uri: Uri): StagedApk {
        val tmp = File.createTempFile("scan_", ".apk", appContext.cacheDir)
        try {
            val md = MessageDigest.getInstance("SHA-256")
            val input = appContext.contentResolver.openInputStream(uri)
                ?: throw InvalidApkException("Faylni ochib bo'lmadi")
            input.use { src ->
                tmp.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val n = src.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_APK_BYTES) throw InvalidApkException("Fayl juda katta (>200 MB)")
                        md.update(buf, 0, n)
                        out.write(buf, 0, n)
                    }
                }
            }
            if (!hasZipMagic(tmp)) throw InvalidApkException("Bu APK emas (zip emas)")
            return StagedApk(tmp, md.digest().toHex())
        } catch (e: Throwable) {
            tmp.delete()
            throw e
        }
    }

    suspend fun analyzeFile(staged: StagedApk): RiskReport = withContext(Dispatchers.IO) {
        val info = archiveInfo(staged.file.path) ?: throw InvalidApkException("APK o'qilmadi yoki buzilgan")
        buildReport(info, staged.file.path, staged.sha256, installed = false)
    }

    // ---------- Asosiy mantiq ----------
    private fun buildReport(info: PackageInfo, apkPath: String?, sha: String?, installed: Boolean): RiskReport {
        val app = info.applicationInfo
        val perms = info.requestedPermissions?.toList().orEmpty()
        val services = info.services.orEmpty()
        val receivers = info.receivers.orEmpty()

        val certs = signatures(info)
        val certHashes = certs.map { sha256Of(it.toByteArray()) }
        val (payload, tgBot) = apkPath?.let { scanZip(it) } ?: (false to false)

        val signals = Signals(
            accessibilityService = services.any { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" },
            deviceAdmin = receivers.any { it.permission == "android.permission.BIND_DEVICE_ADMIN" },
            notificationListener = services.any { it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" },
            telegramBotApi = tgBot,
            embeddedPayload = payload,
            unsigned = certs.isEmpty(),
            debugCert = certs.any(::isDebugCert),
            noLauncher = installed && pm.getLaunchIntentForPackage(info.packageName) == null,
            debuggable = app != null && (app.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
            targetSdk = app?.targetSdkVersion,
            installerPlay = installed && installerOf(info.packageName) == "com.android.vending",
            hashBlacklisted = sha != null && blacklist.contains("sha256", sha),
            certBlacklisted = certHashes.any { blacklist.contains("cert", it) },
        )
        val (score, reasons) = RiskScoring.compute(perms, signals)

        if (!installed && app != null && apkPath != null) {
            app.sourceDir = apkPath; app.publicSourceDir = apkPath // etiketni o'qish uchun
        }
        val label = runCatching { app?.loadLabel(pm)?.toString() }.getOrNull()
        return RiskReport(info.packageName, label, sha, score, RiskScoring.levelFor(score), reasons)
    }

    // ---------- PackageManager yordamchilari ----------
    private val flags: Int = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or
        PackageManager.GET_RECEIVERS or signFlag()

    @Suppress("DEPRECATION")
    private fun signFlag(): Int =
        if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES

    @Suppress("DEPRECATION")
    private fun installedInfo(pkg: String): PackageInfo =
        if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags.toLong()))
        else pm.getPackageInfo(pkg, flags)

    @Suppress("DEPRECATION")
    private fun archiveInfo(path: String): PackageInfo? =
        if (Build.VERSION.SDK_INT >= 33) pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(flags.toLong()))
        else pm.getPackageArchiveInfo(path, flags)

    @Suppress("DEPRECATION")
    private fun signatures(info: PackageInfo): List<Signature> =
        (if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures)?.toList().orEmpty()

    @Suppress("DEPRECATION")
    private fun installerOf(pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else pm.getInstallerPackageName(pkg)
    }.getOrNull()

    private fun isDebugCert(sig: Signature): Boolean = runCatching {
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(sig.toByteArray())) as X509Certificate
        cert.subjectX500Principal.name.contains("Android Debug", ignoreCase = true)
    }.getOrDefault(false)

    // ---------- Zip skaneri: yashirin payload va Telegram Bot API izi ----------
    private fun scanZip(path: String): Pair<Boolean, Boolean> {
        var payload = false
        var tgBot = false
        runCatching {
            ZipFile(path).use { zf ->
                var count = 0
                val en = zf.entries()
                while (en.hasMoreElements() && count++ < MAX_ENTRIES) {
                    val e = en.nextElement()
                    val n = e.name.lowercase()
                    if ((n.startsWith("assets/") || n.startsWith("res/raw/")) &&
                        (n.endsWith(".apk") || n.endsWith(".dex") || n.endsWith(".jar"))
                    ) payload = true
                    if (!tgBot && DEX_NAME.matches(n)) {
                        zf.getInputStream(e).use { if (containsBytes(it, TG_NEEDLE, MAX_DEX_BYTES)) tgBot = true }
                    }
                }
            }
        }
        return payload to tgBot
    }

    private fun containsBytes(input: InputStream, needle: ByteArray, limit: Long): Boolean {
        val buf = ByteArray(64 * 1024)
        var carry = ByteArray(0)
        var total = 0L
        while (total < limit) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            val window = carry + buf.copyOf(n)
            if (indexOf(window, needle) >= 0) return true
            carry = window.copyOfRange(maxOf(0, window.size - (needle.size - 1)), window.size)
        }
        return false
    }

    private fun indexOf(h: ByteArray, n: ByteArray): Int {
        outer@ for (i in 0..h.size - n.size) {
            for (j in n.indices) if (h[i + j] != n[j]) continue@outer
            return i
        }
        return -1
    }

    private fun hasZipMagic(f: File): Boolean = f.inputStream().use {
        val m = ByteArray(4)
        it.read(m) == 4 && m[0] == 'P'.code.toByte() && m[1] == 'K'.code.toByte() && m[2] == 3.toByte() && m[3] == 4.toByte()
    }

    private fun sha256Of(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { s ->
            val buf = ByteArray(64 * 1024)
            while (true) { val n = s.read(buf); if (n < 0) break; md.update(buf, 0, n) }
        }
        return md.digest().toHex()
    }

    private fun sha256Of(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).toHex()
    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    private companion object {
        const val MAX_APK_BYTES = 200L * 1024 * 1024
        const val MAX_DEX_BYTES = 64L * 1024 * 1024
        const val MAX_ENTRIES = 20_000
        val DEX_NAME = Regex("classes\\d*\\.dex")
        val TG_NEEDLE = "api.telegram.org/bot".toByteArray(Charsets.US_ASCII)
    }
}
