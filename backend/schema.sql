-- PostgreSQL sxemasi (SQLAlchemy create_all bilan bir xil). Qo'lda migratsiya uchun.
CREATE TABLE IF NOT EXISTS indicators (
    id          SERIAL PRIMARY KEY,
    kind        VARCHAR(16)  NOT NULL CHECK (kind IN ('sha256','domain','tg_handle','package','cert')),
    value       VARCHAR(512) NOT NULL,
    severity    INTEGER      NOT NULL DEFAULT 80,
    status      VARCHAR(16)  NOT NULL DEFAULT 'pending' CHECK (status IN ('active','pending','revoked')),
    source      VARCHAR(64)  NOT NULL DEFAULT 'manual',
    updated_at  BIGINT       NOT NULL,
    UNIQUE (kind, value)
);
CREATE INDEX IF NOT EXISTS ix_indicators_updated ON indicators (updated_at);

CREATE TABLE IF NOT EXISTS analysis_log (
    sha256       VARCHAR(64) PRIMARY KEY,
    package      VARCHAR(256) NOT NULL DEFAULT '',
    risk_score   INTEGER NOT NULL DEFAULT 0,
    risk_level   VARCHAR(16) NOT NULL DEFAULT 'LOW',
    analyzed_at  BIGINT NOT NULL
);
