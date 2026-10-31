"""Ma'lumotlar bazasi: PostgreSQL (production) yoki SQLite (dev)."""
from __future__ import annotations

import os
import time

from sqlalchemy import BigInteger, Index, Integer, String, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./secguard.db")
# Production: postgresql+psycopg://user:pass@host:5432/secguard
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

KINDS = {"sha256", "domain", "tg_handle", "package", "cert"}
STATUSES = {"active", "pending", "revoked"}


def now_ms() -> int:
    return int(time.time() * 1000)


class Base(DeclarativeBase):
    pass


class Indicator(Base):
    """Qora ro'yxat yozuvi. Klientlarga faqat 'active' va 'revoked' sinxronlanadi."""
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("kind", "value"), Index("ix_indicators_updated", "updated_at"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(512))
    severity: Mapped[int] = mapped_column(Integer, default=80)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    source: Mapped[str] = mapped_column(String(64), default="manual")
    updated_at: Mapped[int] = mapped_column(BigInteger, default=now_ms)


class AnalysisLog(Base):
    """Faqat xesh va natija saqlanadi — yuklangan APK faylning o'zi HECH QACHON saqlanmaydi."""
    __tablename__ = "analysis_log"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    package: Mapped[str] = mapped_column(String(256), default="")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), default="LOW")
    analyzed_at: Mapped[int] = mapped_column(BigInteger, default=now_ms)


def init_db() -> None:
    Base.metadata.create_all(engine)
