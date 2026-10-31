package uz.secguard.core

/**
 * URL / Telegram havola tekshiruvchisi (qurilmada, tarmoqsiz).
 * Havola HECH QACHON ochilmaydi. Mantiq backend `url_guard.py` bilan bir xil.
 */
object UrlGuard {
    enum class Verdict { SAFE, SUSPICIOUS, DANGEROUS }
    data class Reason(val code: String, val points: Int, val text: String)
    data class Result(val url: String, val host: String, val score: Int, val verdict: Verdict, val reasons: List<Reason>)

    private val OFFICIAL = setOf(
        "telegram.org", "t.me", "telegram.me", "telegram.dog", "telesco.pe", "google.com", "gstatic.com",
        "youtube.com", "facebook.com", "instagram.com", "whatsapp.com", "paypal.com", "binance.com",
        "tiktok.com", "apple.com", "microsoft.com", "payme.uz", "uzum.uz", "click.uz", "humocard.uz", "uzcard.uz",
    )
    private val BRANDS = listOf(
        "telegram", "whatsapp", "google", "instagram", "facebook", "paypal", "binance",
        "tiktok", "apple", "microsoft", "payme", "uzum", "uzcard", "humo",
    )
    private val TELEGRAM_HOSTS = setOf("t.me", "telegram.me", "telegram.dog")
    private val SHORTENERS = setOf("bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "rb.gy", "shorturl.at", "clck.ru", "goo.gl")
    private val RISKY_TLDS = setOf("zip", "mov", "top", "xyz", "icu", "tk", "ml", "ga", "cf", "gq", "sbs", "cfd", "click", "work", "rest")
    private val SECOND_LEVEL = setOf("co.uk", "com.uz", "org.uz", "net.uz", "gov.uz", "com.tr", "com.ru", "co.in", "com.au")
    private val APK_EXT = listOf(".apk", ".xapk", ".apks", ".apkm")
    private val KEYWORDS = Regex(
        "(mod|crack|hack|premium|unlock|free[-_]?(?:robux|vbucks|gems|coins)|generator|prize|bonus|giveaway|verify|login|update-now)",
        RegexOption.IGNORE_CASE,
    )
    private val LEET = mapOf('0' to 'o', '1' to 'l', '3' to 'e', '5' to 's', '@' to 'a', '$' to 's')
    private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val SCHEME = Regex("^([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)$", RegexOption.DOT_MATCHES_ALL)
    private val SPLIT = Regex("[.\\-_]")

    private class Parsed(val scheme: String, val host: String, val port: Int?, val hasUserInfo: Boolean, val path: String, val query: String)

    fun check(raw: String, blacklist: BlacklistLookup? = null): Result {
        val input = raw.trim()
        if (input.length > 2048) return Result(input.take(80), "", 40, Verdict.SUSPICIOUS, listOf(Reason("too_long", 40, "Havola haddan tashqari uzun")))
        val p = parse(input) ?: return Result(input, "", 50, Verdict.SUSPICIOUS, listOf(Reason("malformed", 50, "Havola formati noto'g'ri")))
        if (p.host.isEmpty()) return Result(input, "", 50, Verdict.SUSPICIOUS, listOf(Reason("no_host", 50, "Domen topilmadi")))

        val host = p.host
        val reasons = mutableListOf<Reason>()
        fun add(code: String, pts: Int, text: String) { reasons += Reason(code, pts, text) }

        // 1) Qora ro'yxat: host va barcha ota-domenlar
        if (blacklist != null) {
            val labels = host.split(".")
            for (i in 0 until labels.size - 1) {
                if (blacklist.contains("domain", labels.drop(i).joinToString("."))) {
                    return Result(input, host, 100, Verdict.DANGEROUS, listOf(Reason("blacklist", 100, "Domen qora ro'yxatda")))
                }
            }
        }

        // 2) Telegram
        val segs = p.path.split("/").filter { it.isNotEmpty() }
        if (host in TELEGRAM_HOSTS && segs.isNotEmpty()) {
            val handle = segs[0].trimStart('+').lowercase()
            if (blacklist?.contains("tg_handle", handle) == true) {
                return Result(input, host, 100, Verdict.DANGEROUS, listOf(Reason("blacklist", 100, "Telegram akkaunt/bot qora ro'yxatda")))
            }
            if (handle.endsWith("bot")) {
                add("tg_bot", 10, "Telegram bot havolasi: bot nima so'rayotganiga (kod, karta, APK) e'tibor bering")
                if (Regex("(^|&)start=").containsMatchIn(p.query)) add("tg_start_payload", 5, "Bot havolasida start parametri bor")
            }
        }

        // 3) Host belgilari
        if (host.startsWith("[") || IPV4.matches(host)) add("ip_host", 25, "Domen o'rniga IP manzil ishlatilgan")
        if (p.hasUserInfo) add("userinfo", 25, "Havolada '@' bor: haqiqiy manzil yashirilgan bo'lishi mumkin")
        if (host.startsWith("xn--") || ".xn--" in host) add("punycode", 25, "Punycode (IDN) domen: o'xshash harflar orqali aldash mumkin")
        if (mixedScript(host)) add("mixed_script", 25, "Domenda lotin va boshqa alifbo harflari aralash")
        if (host in SHORTENERS) add("shortener", 15, "Qisqartirilgan havola: ichidagi manzil ko'rinmaydi (biz ochmaymiz)")
        val tld = host.substringAfterLast('.')
        if (tld in RISKY_TLDS) add("risky_tld", 12, "Shubhali zona: .$tld")
        if (host.count { it == '.' } >= 4) add("deep_subdomain", 10, "Subdomenlar juda ko'p")
        if (p.port != null && p.port != 80 && p.port != 443) add("odd_port", 5, "G'alati port: ${p.port}")
        if (p.scheme == "http") add("no_tls", 8, "Shifrlanmagan (HTTP) ulanish")
        if (input.length > 100) add("long_url", 5, "Havola juda uzun")

        // 4) Brend taqlidi
        val reg = registeredDomain(host)
        if (reg !in OFFICIAL) brandFinding(host, reg)?.let { reasons += it }

        // 5) APK yuklash va kalit so'zlar
        if (APK_EXT.any { p.path.lowercase().endsWith(it) }) add("apk_download", 30, "Havola to'g'ridan-to'g'ri APK yuklaydi")
        val kw = KEYWORDS.findAll(host + p.path).map { it.value.lowercase() }.toSortedSet()
        if (kw.isNotEmpty()) add("keywords", minOf(20, 10 * kw.size), "Shubhali so'zlar: " + kw.joinToString(", "))

        val score = reasons.sumOf { it.points }.coerceAtMost(100)
        val verdict = when { score >= 70 -> Verdict.DANGEROUS; score >= 30 -> Verdict.SUSPICIOUS; else -> Verdict.SAFE }
        return Result(input, host, score, verdict, reasons.sortedByDescending { it.points })
    }

    private fun brandFinding(host: String, reg: String): Reason? {
        for (tok in host.split(SPLIT).filter { it.isNotEmpty() }) {
            val norm = tok.map { LEET[it] ?: it }.joinToString("")
            for (brand in BRANDS) {
                if (tok == brand) return Reason("brand_in_host", 30, "'$brand' nomi rasmiy bo'lmagan domenda: $reg")
                if (brand.length >= 5 && (norm == brand || levenshtein(tok, brand) <= 1)) {
                    return Reason("typosquat", 35, "'$tok' — '$brand' ga o'xshatib yozilgan")
                }
            }
        }
        return null
    }

    private fun parse(raw: String): Parsed? {
        val m = SCHEME.find(raw)
        val scheme = m?.groupValues?.get(1)?.lowercase() ?: "http"
        val rest = m?.groupValues?.get(2) ?: raw
        val authEnd = rest.indexOfAny(charArrayOf('/', '?', '#')).let { if (it < 0) rest.length else it }
        val authority = rest.substring(0, authEnd)
        val tail = rest.substring(authEnd).substringBefore('#')
        val path = tail.substringBefore('?')
        val query = if ('?' in tail) tail.substringAfter('?') else ""

        val hasUser = '@' in authority
        val hostPort = authority.substringAfterLast('@')
        var host = hostPort
        var port: Int? = null
        if (hostPort.startsWith("[")) {
            val end = hostPort.indexOf(']')
            if (end < 0) return null
            host = hostPort.substring(0, end + 1)
            val after = hostPort.substring(end + 1)
            if (after.startsWith(":") && after.length > 1) port = after.drop(1).toIntOrNull() ?: return null
        } else if (':' in hostPort) {
            host = hostPort.substringBeforeLast(':')
            val ps = hostPort.substringAfterLast(':')
            if (ps.isNotEmpty()) port = ps.toIntOrNull() ?: return null
        }
        return Parsed(scheme, host.lowercase().trimEnd('.'), port, hasUser, path, query)
    }

    private fun mixedScript(text: String): Boolean {
        val latin = text.any { it.lowercaseChar() in 'a'..'z' }
        val other = text.any { it.code > 127 && it.isLetter() }
        return latin && other
    }

    private fun registeredDomain(host: String): String {
        val l = host.split(".")
        if (l.size >= 3 && l.takeLast(2).joinToString(".") in SECOND_LEVEL) return l.takeLast(3).joinToString(".")
        return if (l.size >= 2) l.takeLast(2).joinToString(".") else host
    }

    internal fun levenshtein(a: String, b: String): Int {
        if (a == b) return 0
        var prev = IntArray(b.length + 1) { it }
        for (i in 1..a.length) {
            val cur = IntArray(b.length + 1)
            cur[0] = i
            for (j in 1..b.length) {
                cur[j] = minOf(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + if (a[i - 1] == b[j - 1]) 0 else 1)
            }
            prev = cur
        }
        return prev[b.length]
    }
}
