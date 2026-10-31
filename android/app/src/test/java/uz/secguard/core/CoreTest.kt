package uz.secguard.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** backend/test_core.py bilan bir xil natijalar kutiladi (parity). Ishga tushirish: ./gradlew testDebugUnitTest */
class CoreTest {
    private fun perms(vararg p: String) = p.map { "android.permission.$it" }

    @Test fun benignAppIsLow() {
        val (score, _) = RiskScoring.compute(perms("INTERNET", "CAMERA"), Signals())
        assertEquals(3, score)
        assertEquals(RiskLevel.LOW, RiskScoring.levelFor(score))
    }

    @Test fun smsStealerPattern() {
        val (score, reasons) = RiskScoring.compute(
            perms("READ_SMS", "RECEIVE_SMS", "INTERNET", "RECEIVE_BOOT_COMPLETED"), Signals(noLauncher = true),
        )
        val codes = reasons.map { it.code }
        assertTrue("combo:sms_exfil" in codes && "combo:sms_persistent" in codes)
        assertTrue(RiskScoring.levelFor(score) >= RiskLevel.HIGH)
    }

    @Test fun overlayBankerIsCritical() {
        val (score, _) = RiskScoring.compute(
            perms("SYSTEM_ALERT_WINDOW", "READ_SMS", "REQUEST_INSTALL_PACKAGES"),
            Signals(accessibilityService = true, telegramBotApi = true),
        )
        assertTrue(score >= 80)
    }

    @Test fun blacklistAndPlayFactor() {
        assertEquals(100, RiskScoring.compute(emptyList(), Signals(hashBlacklisted = true)).first)
        val p = perms("READ_SMS", "INTERNET")
        assertTrue(RiskScoring.compute(p, Signals(installerPlay = true)).first < RiskScoring.compute(p, Signals()).first)
    }

    @Test fun officialUrlsAreSafe() {
        listOf("https://telegram.org/faq", "https://t.me/durov", "https://www.google.com/search?q=a")
            .forEach { assertEquals(it, UrlGuard.Verdict.SAFE, UrlGuard.check(it).verdict) }
    }

    @Test fun typosquatAndApkAndIp() {
        assertTrue(UrlGuard.check("https://te1egram.org/premium").score >= 35)
        assertTrue(UrlGuard.check("https://example.com/app-mod.apk").reasons.any { it.code == "apk_download" })
        assertTrue(UrlGuard.check("http://185.12.4.9/login").reasons.any { it.code == "ip_host" })
        assertTrue(UrlGuard.check("https://telegram.org@evil.top/x").reasons.any { it.code == "userinfo" })
        assertEquals(UrlGuard.Verdict.DANGEROUS, UrlGuard.check("http://telegram.org@185.1.1.1/mod-premium.apk").verdict)
    }

    @Test fun blacklistMatchesSuffixAndTelegramHandle() {
        val bl = setOf("domain" to "evil.example", "tg_handle" to "scamvipbot")
        val lookup = BlacklistLookup { k, v -> (k to v) in bl }
        assertEquals(100, UrlGuard.check("https://login.evil.example/a", lookup).score)
        assertEquals(100, UrlGuard.check("https://t.me/ScamVipBot?start=ref", lookup).score)
        assertEquals(UrlGuard.Verdict.SAFE, UrlGuard.check("https://t.me/SomeHelperBot", lookup).verdict)
    }

    @Test fun malformedAndLevenshtein() {
        assertEquals(UrlGuard.Verdict.SUSPICIOUS, UrlGuard.check("http://[::1").verdict)
        assertEquals(UrlGuard.Verdict.SUSPICIOUS, UrlGuard.check("").verdict)
        assertEquals(3, UrlGuard.levenshtein("kitten", "sitting"))
    }
}
