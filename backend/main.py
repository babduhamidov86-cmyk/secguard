"""SecGuard backend: FastAPI.

Ishga tushirish:  uvicorn main:app --host 0.0.0.0 --port 8000
Muhit o'zgaruvchilari: DATABASE_URL, API_KEY (klientlar), ADMIN_KEY (qora ro'yxatni boshqarish)
Production'da TLS (reverse proxy) va rate-limit (nginx / slowapi) majburiy.
"""
from __future__ import annotations

import os
import re
import secrets
import tempfile
from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import select

from analyzer import AnalysisError, analyze_apk
from db import KINDS, STATUSES, AnalysisLog, Indicator, SessionLocal, init_db, now_ms
from url_guard import check_url

MAX_UPLOAD = 100 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SYNC_PAGE = 2000


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="SecGuard API", version="1.0.0", lifespan=lifespan)


def _check_key(provided: str | None, env_name: str) -> None:
    expected = os.getenv(env_name)
    if not expected:
        raise HTTPException(503, f"{env_name} sozlanmagan")
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(401, "Noto'g'ri kalit")


def require_client(x_api_key: str | None = Header(default=None)) -> None:
    _check_key(x_api_key, "API_KEY")


def require_admin(x_admin_key: str | None = Header(default=None)) -> None:
    _check_key(x_admin_key, "ADMIN_KEY")


def _active_lookup(session):
    def lookup(kind: str, value: str) -> bool:
        row = session.execute(
            select(Indicator.id).where(
                Indicator.kind == kind, Indicator.value == value, Indicator.status == "active"
            )
        ).first()
        return row is not None
    return lookup


# ---------- 1) APK tahlili ----------
@app.post("/v1/analyze/apk", dependencies=[Depends(require_client)])
async def analyze_apk_endpoint(file: UploadFile = File(...)):
    """APK yuklash faqat foydalanuvchi roziligi bilan (ilovada alohida opt-in). Fayl tahlildan keyin o'chiriladi."""
    size = 0
    with tempfile.NamedTemporaryFile(suffix=".bin") as tmp:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > MAX_UPLOAD:
                raise HTTPException(413, "Fayl 100 MB dan katta")
            tmp.write(chunk)
        tmp.flush()

        def work():
            with SessionLocal() as s:
                return analyze_apk(tmp.name, _active_lookup(s))

        try:
            report = await run_in_threadpool(work)
        except AnalysisError as e:
            raise HTTPException(422, str(e)) from e

    with SessionLocal() as s:
        s.merge(AnalysisLog(sha256=report["sha256"], package=report["package"] or "",
                            risk_score=report["risk_score"], risk_level=report["risk_level"],
                            analyzed_at=now_ms()))
        # Avtomatik ball bilan qora ro'yxatga TO'G'RIDAN-TO'G'RI qo'shilmaydi:
        # 'pending' bo'ladi va inson tekshiruvidan keyingina 'active' bo'ladi (false-positive himoyasi).
        if report["risk_score"] >= 80:
            exists = s.execute(select(Indicator.id).where(
                Indicator.kind == "sha256", Indicator.value == report["sha256"])).first()
            if not exists:
                s.add(Indicator(kind="sha256", value=report["sha256"], severity=report["risk_score"],
                                status="pending", source="auto", updated_at=now_ms()))
        s.commit()
    return report


# ---------- 2) Xesh va URL tekshiruvi ----------
class HashQuery(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)


class UrlQuery(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


@app.post("/v1/lookup/hash", dependencies=[Depends(require_client)])
def lookup_hash(q: HashQuery):
    h = q.sha256.lower()
    if not SHA256_RE.match(h):
        raise HTTPException(422, "SHA-256 formati noto'g'ri")
    with SessionLocal() as s:
        known = _active_lookup(s)("sha256", h)
        log = s.get(AnalysisLog, h)
    return {"sha256": h, "blacklisted": known,
            "previous_analysis": None if not log else
            {"risk_score": log.risk_score, "risk_level": log.risk_level, "package": log.package}}


@app.post("/v1/url/check", dependencies=[Depends(require_client)])
def url_check(q: UrlQuery):
    with SessionLocal() as s:
        verdict = check_url(q.url, _active_lookup(s))
    return asdict(verdict)


# ---------- 3) Qora ro'yxat sinxronizatsiyasi ----------
@app.get("/v1/blacklist/sync", dependencies=[Depends(require_client)])
def blacklist_sync(since: int = Query(0, ge=0)):
    """`since` (ms) dan keyingi o'zgarishlar. Klient `has_more` bo'lsa `next_since` bilan davom etadi."""
    with SessionLocal() as s:
        rows = s.execute(
            select(Indicator)
            .where(Indicator.updated_at >= since, Indicator.status.in_(("active", "revoked")))
            .order_by(Indicator.updated_at, Indicator.id)
            .limit(SYNC_PAGE)
        ).scalars().all()
    next_since = rows[-1].updated_at if rows else since
    return {
        "server_time": now_ms(),
        "next_since": next_since,
        "has_more": len(rows) == SYNC_PAGE,
        "items": [{"kind": r.kind, "value": r.value, "severity": r.severity, "status": r.status} for r in rows],
    }


# ---------- 4) Admin: indikatorlarni boshqarish ----------
class IndicatorIn(BaseModel):
    kind: str
    value: str = Field(min_length=1, max_length=512)
    severity: int = Field(80, ge=0, le=100)
    status: str = "active"
    source: str = "manual"


@app.post("/v1/admin/indicators", dependencies=[Depends(require_admin)])
def upsert_indicator(item: IndicatorIn):
    if item.kind not in KINDS or item.status not in STATUSES:
        raise HTTPException(422, "kind yoki status noto'g'ri")
    value = item.value.strip().lower()
    if item.kind in ("sha256", "cert") and not SHA256_RE.match(value):
        raise HTTPException(422, "SHA-256 formati noto'g'ri")
    with SessionLocal() as s:
        row = s.execute(select(Indicator).where(
            Indicator.kind == item.kind, Indicator.value == value)).scalar_one_or_none()
        if row is None:
            row = Indicator(kind=item.kind, value=value)
            s.add(row)
        row.severity, row.status, row.source, row.updated_at = item.severity, item.status, item.source, now_ms()
        s.commit()
    return {"ok": True}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
