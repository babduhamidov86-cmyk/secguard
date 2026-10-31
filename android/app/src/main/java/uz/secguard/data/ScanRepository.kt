package uz.secguard.data

import android.content.pm.PackageManager
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import uz.secguard.core.ApkStaticAnalyzer
import uz.secguard.core.BlacklistLookup
import uz.secguard.core.RiskLevel
import uz.secguard.core.RiskReason
import uz.secguard.core.RiskReport
import uz.secguard.core.RiskScoring
import uz.secguard.core.UrlGuard

/**
 * Lokal tahlil + (faqat rozilik bo'lsa) server bilan boyitish.
 * Server xatosi lokal natijani hech qachon buzmaydi: tarmoq ishlamasa lokal natija qaytadi.
 */
class ScanRepository(
    private val analyzer: ApkStaticAnalyzer,
    private val api: ApiClient,
    private val consent: ConsentStore,
    private val blacklist: BlacklistLookup,
) {
    /** @throws PackageManager.NameNotFoundException paket ko'rinmasa */
    suspend fun scanInstalled(pkg: String): RiskReport = enrichWithHash(analyzer.analyzeInstalled(pkg))

    suspend fun scanApk(uri: Uri): RiskReport = withContext(Dispatchers.IO) {
        val staged = analyzer.stage(uri)
        try {
            var report = analyzer.analyzeFile(staged)
            if (consent.apkUpload) {
                runCatching { api.uploadApk(staged.file) }.getOrNull()?.let { report = mergeServer(report, it) }
            }
            enrichWithHash(report)
        } finally {
            staged.file.delete()
        }
    }

    suspend fun checkUrl(raw: String): UrlGuard.Result = withContext(Dispatchers.IO) {
        val local = UrlGuard.check(raw, blacklist)
        if (!consent.serverLookup || local.score == 100) return@withContext local
        val remote = runCatching { api.checkUrl(raw) }.getOrNull() ?: return@withContext local
        if (remote.optInt("score", 0) <= local.score) local else toUrlResult(raw, remote)
    }

    private suspend fun enrichWithHash(r: RiskReport): RiskReport = withContext(Dispatchers.IO) {
        val sha = r.sha256
        if (!consent.serverLookup || sha == null || r.score >= 100) return@withContext r
        val hit = runCatching { api.lookupHash(sha) }.getOrNull() ?: return@withContext r
        if (!hit) r else r.copy(
            score = 100, level = RiskLevel.CRITICAL,
            reasons = listOf(RiskReason("server_blacklist", 100, "Server qora ro'yxatida")) + r.reasons,
        )
    }

    private fun mergeServer(local: RiskReport, server: JSONObject): RiskReport {
        val score = server.optInt("risk_score", 0)
        if (score <= local.score) return local
        val arr = server.optJSONArray("reasons")
        val reasons = if (arr == null) local.reasons else List(arr.length()) {
            val o = arr.getJSONObject(it)
            RiskReason(o.getString("code"), o.getInt("points"), o.getString("text"))
        }
        return local.copy(score = score, level = RiskScoring.levelFor(score), reasons = reasons)
    }

    private fun toUrlResult(raw: String, j: JSONObject): UrlGuard.Result {
        val arr = j.optJSONArray("reasons")
        val reasons = if (arr == null) emptyList() else List(arr.length()) {
            val o = arr.getJSONObject(it)
            UrlGuard.Reason(o.getString("code"), o.getInt("points"), o.getString("text"))
        }
        val verdict = when (j.optString("verdict")) {
            "dangerous" -> UrlGuard.Verdict.DANGEROUS
            "suspicious" -> UrlGuard.Verdict.SUSPICIOUS
            else -> UrlGuard.Verdict.SAFE
        }
        return UrlGuard.Result(raw, j.optString("host"), j.optInt("score"), verdict, reasons)
    }
}
