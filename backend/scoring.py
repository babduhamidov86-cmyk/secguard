"""Risk Score (0-100) hisoblash.

Bu modul faqat sof mantiq (fayl/tarmoq yo'q), shuning uchun oson test qilinadi.
Vaznlar Kotlin tomondagi `RiskScoring.kt` bilan BIR XIL bo'lishi shart.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

# Faqat uses-permission sifatida so'raladigan ruxsatlar (qisqa nom: android.permission.XXX).
# BIND_* ruxsatlari servis darajasida e'lon qilinadi -> signals orqali hisoblanadi.
PERMISSION_WEIGHTS: dict[str, int] = {
    "READ_SMS": 18,
    "RECEIVE_SMS": 18,
    "SEND_SMS": 15,
    "READ_CALL_LOG": 10,
    "SYSTEM_ALERT_WINDOW": 14,
    "REQUEST_INSTALL_PACKAGES": 12,
    "RECORD_AUDIO": 8,
    "READ_CONTACTS": 6,
    "MANAGE_EXTERNAL_STORAGE": 6,
    "DISABLE_KEYGUARD": 6,
    "PACKAGE_USAGE_STATS": 6,
    "QUERY_ALL_PACKAGES": 5,
    "RECEIVE_BOOT_COMPLETED": 4,
    "CALL_PHONE": 4,
    "WRITE_SETTINGS": 4,
    "READ_PHONE_STATE": 3,
    "REQUEST_DELETE_PACKAGES": 3,
    "CAMERA": 3,
    "ACCESS_FINE_LOCATION": 3,
}

SIGNAL_WEIGHTS: dict[str, tuple[int, str]] = {
    "accessibility_service": (22, "Accessibility xizmati e'lon qilingan"),
    "device_admin": (20, "Device Admin qabul qiluvchisi e'lon qilingan"),
    "notification_listener": (14, "Bildirishnomalarni o'qish xizmati (OTP o'g'irlash xavfi)"),
    "telegram_bot_api": (20, "Kod ichida Telegram Bot API manzili bor (ma'lumot yuborish ehtimoli)"),
    "embedded_payload": (12, "Ilova ichida yashirin .apk/.dex fayl bor"),
    "unsigned": (12, "Ilova imzolanmagan"),
    "debug_cert": (10, "Debug sertifikati bilan imzolangan"),
    "no_launcher": (8, "Ishga tushirish ikonkasi yo'q (yashirin ilova)"),
    "low_target_sdk": (6, "Eski targetSdk (<23): ruxsatlar so'ralmasdan beriladi"),
    "debuggable": (5, "debuggable=true"),
}

COMBO_WEIGHTS: list[tuple[str, int, str]] = [
    ("sms_exfil", 10, "SMS o'qish + internet: SMS/OTP uzatish xavfi"),
    ("overlay_banker", 15, "Overlay + Accessibility: soxta oyna orqali ma'lumot o'g'irlash namunasi"),
    ("dropper", 15, "O'rnatish ruxsati + yashirin payload: dropper namunasi"),
    ("sms_persistent", 6, "SMS + qurilma yoqilganda avto-ishga tushish"),
]

PLAY_INSTALL_FACTOR = 0.6  # Google Play'dan o'rnatilgan bo'lsa ball kamaytiriladi


@dataclass
class Signals:
    accessibility_service: bool = False
    device_admin: bool = False
    notification_listener: bool = False
    telegram_bot_api: bool = False
    embedded_payload: bool = False
    unsigned: bool = False
    debug_cert: bool = False
    no_launcher: bool = False
    debuggable: bool = False
    target_sdk: int | None = None
    installer_play: bool = False
    hash_blacklisted: bool = False
    cert_blacklisted: bool = False


@dataclass
class Reason:
    code: str
    points: int
    text: str


@dataclass
class RiskResult:
    score: int
    level: str
    reasons: list[Reason] = field(default_factory=list)


def short_name(permission: str) -> str:
    return permission.rsplit(".", 1)[-1].upper()


def level_for(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def compute_risk(permissions: Iterable[str], s: Signals) -> RiskResult:
    perms = {short_name(p) for p in permissions}

    if s.hash_blacklisted or s.cert_blacklisted:
        why = "SHA-256 qora ro'yxatda" if s.hash_blacklisted else "Imzo sertifikati qora ro'yxatda"
        return RiskResult(100, "CRITICAL", [Reason("blacklisted", 100, why)])

    reasons: list[Reason] = []

    for name in sorted(perms):
        w = PERMISSION_WEIGHTS.get(name)
        if w:
            reasons.append(Reason(f"perm:{name}", w, f"Xavfli ruxsat: {name}"))

    for key, (w, text) in SIGNAL_WEIGHTS.items():
        if key == "low_target_sdk":
            active = s.target_sdk is not None and s.target_sdk < 23
        else:
            active = bool(getattr(s, key))
        if active:
            reasons.append(Reason(f"sig:{key}", w, text))

    sms = bool(perms & {"READ_SMS", "RECEIVE_SMS"})
    combos = {
        "sms_exfil": sms and "INTERNET" in perms,
        "overlay_banker": "SYSTEM_ALERT_WINDOW" in perms and s.accessibility_service,
        "dropper": "REQUEST_INSTALL_PACKAGES" in perms and s.embedded_payload,
        "sms_persistent": sms and "RECEIVE_BOOT_COMPLETED" in perms,
    }
    for code, w, text in COMBO_WEIGHTS:
        if combos[code]:
            reasons.append(Reason(f"combo:{code}", w, text))

    raw = sum(r.points for r in reasons)
    if s.installer_play:
        raw = int(raw * PLAY_INSTALL_FACTOR)
    score = max(0, min(100, raw))
    reasons.sort(key=lambda r: -r.points)
    return RiskResult(score, level_for(score), reasons)
