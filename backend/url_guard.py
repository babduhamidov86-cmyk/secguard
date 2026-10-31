"""URL / Telegram havola tekshiruvchisi.

MUHIM: bu modul havolani HECH QACHON ochmaydi (SSRF va zararli kontentni
yuklab olish xavfi yo'q). Faqat matnli evristika + qora ro'yxat bilan ishlaydi.
Natija: 0-100 ball va sabablar ro'yxati. Kotlin `UrlGuard.kt` bilan bir xil mantiq.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qs, urlsplit

# lookup(kind, value) -> bool. kind: "domain" | "tg_handle"
Lookup = Callable[[str, str], bool]

OFFICIAL_DOMAINS = {
    "telegram.org", "t.me", "telegram.me", "telegram.dog", "telesco.pe",
    "google.com", "gstatic.com", "youtube.com", "facebook.com", "instagram.com",
    "whatsapp.com", "paypal.com", "binance.com", "tiktok.com", "apple.com",
    "microsoft.com", "payme.uz", "uzum.uz", "click.uz", "humocard.uz", "uzcard.uz",
}
BRANDS = [
    "telegram", "whatsapp", "google", "instagram", "facebook", "paypal",
    "binance", "tiktok", "apple", "microsoft", "payme", "uzum", "uzcard", "humo",
]
TELEGRAM_HOSTS = {"t.me", "telegram.me", "telegram.dog"}
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "rb.gy", "shorturl.at", "clck.ru", "goo.gl"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "icu", "tk", "ml", "ga", "cf", "gq", "sbs", "cfd", "click", "work", "rest"}
SECOND_LEVEL = {"co.uk", "com.uz", "org.uz", "net.uz", "gov.uz", "com.tr", "com.ru", "co.in", "com.au"}
APK_EXT = (".apk", ".xapk", ".apks", ".apkm")
KEYWORDS = re.compile(r"(mod|crack|hack|premium|unlock|free[-_]?(?:robux|vbucks|gems|coins)|generator|prize|bonus|giveaway|verify|login|update-now)", re.I)
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


@dataclass
class UrlReason:
    code: str
    points: int
    text: str


@dataclass
class UrlVerdict:
    url: str
    host: str
    score: int
    verdict: str  # "safe" | "suspicious" | "dangerous"
    reasons: list[UrlReason] = field(default_factory=list)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _is_mixed_script(text: str) -> bool:
    has_latin = any("a" <= c.lower() <= "z" for c in text)
    has_other = any(ord(c) > 127 and c.isalpha() for c in text)
    return has_latin and has_other


def _verdict(score: int) -> str:
    return "dangerous" if score >= 70 else "suspicious" if score >= 30 else "safe"


def check_url(raw: str, lookup: Lookup | None = None) -> UrlVerdict:
    raw = (raw or "").strip()
    if len(raw) > 2048:
        return UrlVerdict(raw[:80], "", 40, "suspicious", [UrlReason("too_long", 40, "Havola haddan tashqari uzun")])

    candidate = raw if "://" in raw else "http://" + raw
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return UrlVerdict(raw, "", 50, "suspicious", [UrlReason("malformed", 50, "Havola formati noto'g'ri")])
    if not host:
        return UrlVerdict(raw, "", 50, "suspicious", [UrlReason("no_host", 50, "Domen topilmadi")])

    reasons: list[UrlReason] = []

    def add(code: str, pts: int, text: str) -> None:
        reasons.append(UrlReason(code, pts, text))

    # 1) Qora ro'yxat (host va barcha ota-domenlar)
    if lookup:
        labels = host.split(".")
        for i in range(len(labels) - 1):
            if lookup("domain", ".".join(labels[i:])):
                return UrlVerdict(raw, host, 100, "dangerous", [UrlReason("blacklist", 100, "Domen qora ro'yxatda")])

    # 2) Telegram
    segs = [s for s in parts.path.split("/") if s]
    if host in TELEGRAM_HOSTS and segs:
        handle = segs[0].lstrip("+").lower()
        if lookup and lookup("tg_handle", handle):
            return UrlVerdict(raw, host, 100, "dangerous", [UrlReason("blacklist", 100, "Telegram akkaunt/bot qora ro'yxatda")])
        if handle.endswith("bot"):
            add("tg_bot", 10, "Telegram bot havolasi: bot nima so'rayotganiga (kod, karta, APK) e'tibor bering")
            if "start" in parse_qs(parts.query):
                add("tg_start_payload", 5, "Bot havolasida start parametri bor")

    # 3) Host belgilari
    try:
        ipaddress.ip_address(host.strip("[]"))
        add("ip_host", 25, "Domen o'rniga IP manzil ishlatilgan")
    except ValueError:
        pass
    if "@" in parts.netloc:
        add("userinfo", 25, "Havolada '@' bor: haqiqiy manzil yashirilgan bo'lishi mumkin")
    if host.startswith("xn--") or ".xn--" in host:
        add("punycode", 25, "Punycode (IDN) domen: o'xshash harflar orqali aldash mumkin")
    if _is_mixed_script(host):
        add("mixed_script", 25, "Domenda lotin va boshqa alifbo harflari aralash")
    if host in SHORTENERS:
        add("shortener", 15, "Qisqartirilgan havola: ichidagi manzil ko'rinmaydi (biz ochmaymiz)")
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        add("risky_tld", 12, f"Shubhali zona: .{tld}")
    if host.count(".") >= 4:
        add("deep_subdomain", 10, "Subdomenlar juda ko'p")
    if port not in (None, 80, 443):
        add("odd_port", 5, f"G'alati port: {port}")
    if parts.scheme == "http":
        add("no_tls", 8, "Shifrlanmagan (HTTP) ulanish")
    if len(raw) > 100:
        add("long_url", 5, "Havola juda uzun")

    # 4) Brend taqlidi
    reg = registered_domain(host)
    if reg not in OFFICIAL_DOMAINS:
        tokens = [t for t in re.split(r"[.\-_]", host) if t]
        flagged = False
        for tok in tokens:
            norm = tok.translate(LEET)
            for brand in BRANDS:
                if tok == brand:
                    add("brand_in_host", 30, f"'{brand}' nomi rasmiy bo'lmagan domenda: {reg}")
                    flagged = True
                elif len(brand) >= 5 and (norm == brand or levenshtein(tok, brand) <= 1):
                    add("typosquat", 35, f"'{tok}' — '{brand}' ga o'xshatib yozilgan")
                    flagged = True
                if flagged:
                    break
            if flagged:
                break

    # 5) APK yuklab olish va kalit so'zlar
    path_l = parts.path.lower()
    if path_l.endswith(APK_EXT):
        add("apk_download", 30, "Havola to'g'ridan-to'g'ri APK yuklaydi")
    kw = set(m.group(0).lower() for m in KEYWORDS.finditer(host + parts.path))
    if kw:
        add("keywords", min(20, 10 * len(kw)), "Shubhali so'zlar: " + ", ".join(sorted(kw)))

    score = min(100, sum(r.points for r in reasons))
    reasons.sort(key=lambda r: -r.points)
    return UrlVerdict(raw, host, score, _verdict(score), reasons)
