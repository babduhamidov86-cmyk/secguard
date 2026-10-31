"""Tashqi kutubxonasiz testlar:  python3 test_core.py   (yoki pytest)"""
from scoring import Signals, compute_risk, level_for
from url_guard import check_url, levenshtein, registered_domain


def test_benign_app_is_low():
    r = compute_risk(["android.permission.INTERNET", "android.permission.CAMERA"], Signals())
    assert r.level == "LOW" and r.score == 3


def test_sms_stealer_pattern_is_high():
    perms = ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
             "android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"]
    r = compute_risk(perms, Signals(no_launcher=True))
    codes = {x.code for x in r.reasons}
    assert "combo:sms_exfil" in codes and "combo:sms_persistent" in codes
    assert r.level in ("HIGH", "CRITICAL")


def test_overlay_banker_is_critical():
    perms = ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_SMS",
             "android.permission.REQUEST_INSTALL_PACKAGES"]
    r = compute_risk(perms, Signals(accessibility_service=True, telegram_bot_api=True))
    assert r.score >= 80 and r.level == "CRITICAL"


def test_score_capped_and_blacklist():
    perms = [f"android.permission.{p}" for p in
             ["READ_SMS", "RECEIVE_SMS", "SEND_SMS", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "READ_CALL_LOG"]]
    r = compute_risk(perms, Signals(accessibility_service=True, device_admin=True, telegram_bot_api=True))
    assert r.score == 100
    assert compute_risk([], Signals(hash_blacklisted=True)).score == 100


def test_play_installer_reduces_score():
    perms = ["android.permission.READ_SMS", "android.permission.INTERNET"]
    a = compute_risk(perms, Signals()).score
    b = compute_risk(perms, Signals(installer_play=True)).score
    assert b < a


def test_levels():
    assert [level_for(x) for x in (0, 29, 30, 59, 60, 79, 80, 100)] == \
        ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]


def test_url_official_is_safe():
    for u in ("https://telegram.org/faq", "https://t.me/durov", "https://www.google.com/search?q=a"):
        assert check_url(u).verdict == "safe", u


def test_url_typosquat_and_brand_in_host():
    assert check_url("https://te1egram.org/premium").score >= 35
    v = check_url("https://telegram-premium-free.xyz/get")
    assert v.verdict in ("suspicious", "dangerous") and any(r.code == "brand_in_host" for r in v.reasons)


def test_url_apk_ip_userinfo():
    assert any(r.code == "apk_download" for r in check_url("https://example.com/app-mod.apk").reasons)
    assert any(r.code == "ip_host" for r in check_url("http://185.12.4.9/login").reasons)
    assert any(r.code == "userinfo" for r in check_url("https://telegram.org@evil.top/x").reasons)
    assert check_url("http://telegram.org@185.1.1.1/mod-premium.apk").verdict == "dangerous"


def test_url_blacklist_suffix_match():
    bl = {("domain", "evil.example"), ("tg_handle", "scamvipbot")}
    lookup = lambda k, v: (k, v) in bl
    assert check_url("https://login.evil.example/a", lookup).score == 100
    assert check_url("https://t.me/ScamVipBot?start=ref", lookup).score == 100
    assert check_url("https://t.me/SomeHelperBot", lookup).verdict == "safe"


def test_url_malformed_and_helpers():
    assert check_url("http://[::1").verdict == "suspicious"
    assert check_url("").verdict == "suspicious"
    assert levenshtein("kitten", "sitting") == 3
    assert registered_domain("a.b.example.com.uz") == "example.com.uz"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("OK ", t.__name__)
    print(f"{len(tests)} test o'tdi")
