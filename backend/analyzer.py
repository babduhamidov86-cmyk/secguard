"""APK statik tahlilchi (Androguard + libmagic).

Xavfsizlik qoidalari:
  * APK hech qachon ishga tushirilmaydi va arxiv diskka ochilmaydi (extract yo'q).
  * Zip-bomba himoyasi: yozuvlar soni, jami hajm va siqish nisbati cheklangan.
  * Fayl turi kengaytmaga emas, libmagic + zip tuzilmasiga qarab aniqlanadi.
"""
from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import asdict
from typing import Any

import magic
from androguard.core.apk import APK

from scoring import Signals, compute_risk

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAX_ENTRIES = 20_000
MAX_UNCOMPRESSED = 600 * 1024 * 1024
MAX_RATIO = 200
ACCEPTED_MIMES = {
    "application/vnd.android.package-archive",
    "application/zip",
    "application/java-archive",
    "application/x-zip-compressed",
}
TG_BOT_RE = re.compile(rb"api\.telegram\.org/bot")


class AnalysisError(Exception):
    """Foydalanuvchiga ko'rsatish mumkin bo'lgan tahlil xatosi."""


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_container(path: str) -> None:
    mime = magic.from_file(path, mime=True)
    if mime not in ACCEPTED_MIMES:
        raise AnalysisError(f"APK emas: fayl turi {mime}")
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        raise AnalysisError("Zip tuzilmasi buzilgan") from e
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise AnalysisError("Arxivdagi fayllar soni haddan tashqari ko'p")
        total = 0
        for i in infos:
            total += i.file_size
            if i.compress_size and i.file_size / i.compress_size > MAX_RATIO and i.file_size > 10 * 1024 * 1024:
                raise AnalysisError("Shubhali siqish nisbati (zip-bomba)")
        if total > MAX_UNCOMPRESSED:
            raise AnalysisError("Arxiv ochilgandagi hajmi haddan tashqari katta")
        names = set(zf.namelist())
        if "AndroidManifest.xml" not in names:
            raise AnalysisError("AndroidManifest.xml topilmadi: bu APK emas")


def _manifest_signals(apk: APK) -> dict[str, Any]:
    out = dict(accessibility_service=False, device_admin=False, notification_listener=False,
               no_launcher=True, debuggable=False)
    xml = apk.get_android_manifest_xml()
    app = xml.find("application")
    if app is None:
        return out
    out["debuggable"] = str(app.get(ANDROID_NS + "debuggable", "")).lower() == "true"
    for svc in app.iter("service"):
        perm = svc.get(ANDROID_NS + "permission", "")
        if perm == "android.permission.BIND_ACCESSIBILITY_SERVICE":
            out["accessibility_service"] = True
        if perm == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
            out["notification_listener"] = True
    for rcv in app.iter("receiver"):
        if rcv.get(ANDROID_NS + "permission", "") == "android.permission.BIND_DEVICE_ADMIN":
            out["device_admin"] = True
    for act in list(app.iter("activity")) + list(app.iter("activity-alias")):
        for flt in act.iter("intent-filter"):
            cats = {c.get(ANDROID_NS + "name") for c in flt.iter("category")}
            if "android.intent.category.LAUNCHER" in cats:
                out["no_launcher"] = False
    return out


def _cert_info(apk: APK) -> tuple[list[str], bool]:
    hashes: list[str] = []
    debug = False
    try:
        for cert in apk.get_certificates():
            hashes.append(cert.sha256.hex())
            subject = cert.subject.human_friendly
            if "Android Debug" in subject:
                debug = True
    except Exception:
        pass
    return hashes, debug


def _scan_dex_for_telegram(apk: APK) -> bool:
    try:
        for dex in apk.get_all_dex():
            if TG_BOT_RE.search(dex):
                return True
    except Exception:
        pass
    return False


def _embedded_payload(apk: APK) -> bool:
    try:
        for name in apk.get_files():
            low = name.lower()
            if low.startswith(("assets/", "res/raw/")) and low.endswith((".apk", ".dex", ".jar")):
                return True
    except Exception:
        pass
    return False


def _signed_flags(apk: APK) -> bool:
    try:
        return apk.is_signed_v1() or apk.is_signed_v2() or apk.is_signed_v3()
    except Exception:
        return False


def analyze_apk(path: str, is_blacklisted=None) -> dict[str, Any]:
    """Berilgan APK'ni tahlil qiladi. `is_blacklisted(kind, value) -> bool` ixtiyoriy."""
    validate_container(path)
    digest = sha256_file(path)
    try:
        apk = APK(path)
    except Exception as e:  # androguard turli xatolar beradi
        raise AnalysisError(f"APK o'qilmadi: {type(e).__name__}") from e

    permissions = sorted(apk.get_permissions())
    ms = _manifest_signals(apk)
    cert_hashes, debug_cert = _cert_info(apk)
    try:
        target_sdk = int(apk.get_target_sdk_version() or 0) or None
    except (TypeError, ValueError):
        target_sdk = None

    signals = Signals(
        accessibility_service=ms["accessibility_service"],
        device_admin=ms["device_admin"],
        notification_listener=ms["notification_listener"],
        no_launcher=ms["no_launcher"],
        debuggable=ms["debuggable"],
        telegram_bot_api=_scan_dex_for_telegram(apk),
        embedded_payload=_embedded_payload(apk),
        unsigned=not _signed_flags(apk),
        debug_cert=debug_cert,
        target_sdk=target_sdk,
        hash_blacklisted=bool(is_blacklisted and is_blacklisted("sha256", digest)),
        cert_blacklisted=bool(is_blacklisted and any(is_blacklisted("cert", h) for h in cert_hashes)),
    )
    result = compute_risk(permissions, signals)
    return {
        "sha256": digest,
        "package": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version": apk.get_androidversion_name(),
        "target_sdk": target_sdk,
        "permissions": permissions,
        "cert_sha256": cert_hashes,
        "signals": asdict(signals),
        "risk_score": result.score,
        "risk_level": result.level,
        "reasons": [asdict(r) for r in result.reasons],
    }
