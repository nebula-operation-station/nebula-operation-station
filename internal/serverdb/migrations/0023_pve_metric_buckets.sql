-- 0023_pve_metric_buckets.sql
-- PVE metric retention and server-side averages (ADR 0006, ticket P1-25):
-- bounded five-minute aggregates of the fraction-valued box metrics (cpu,
-- ram, disk) the collector spools, plus the current (live) value per series.
--
-- Identity rules (mirror pve_nodes / pve_guests):
--   * Every series carries remote_id.
--   * Node series are keyed by (remote_id, target_kind, node, vmid,
--     generation, metric) with vmid = 0 and generation = 0.
--   * Guest series are keyed by the same tuple with node = '' and
--     generation = the local guest incarnation. A VMID reused after deletion
--     is a new generation, so it starts a fresh series: old buckets are
--     never merged into the new incarnation (and vice versa).
--
-- Retention:
--   * pve_metric_buckets holds at most 288 five-minute buckets per series
--     (24 h). Rows older than the window are removed only by explicit
--     retention (PruneMetrics), never by writes.
--   * Averages are computed from the buckets that actually have samples;
--     empty buckets are never filled with zero. Coverage reports how many of
--     the 288 buckets carry data, so a short history is never presented as a
--     full-day average.
--   * pve_metric_current holds one row per series: the most recent value.
--     The live 10 s sample shares the current 5-min bucket and updates this
--     row. It is bounded (one row per series), not an unbounded raw history.
--
-- No credential material or raw API responses live here.

CREATE TABLE pve_metric_buckets (
    remote_id         TEXT NOT NULL,
    target_kind       TEXT NOT NULL,
    node              TEXT NOT NULL DEFAULT '',
    vmid              INTEGER NOT NULL DEFAULT 0,
    generation        INTEGER NOT NULL DEFAULT 0,
    metric            TEXT NOT NULL,
    bucket_start_unix INTEGER NOT NULL,
    sum               REAL NOT NULL DEFAULT 0,
    count             INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, target_kind, node, vmid, generation, metric, bucket_start_unix)
);
CREATE INDEX idx_pve_metric_buckets_prune ON pve_metric_buckets (bucket_start_unix);

CREATE TABLE pve_metric_current (
    remote_id   TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    node        TEXT NOT NULL DEFAULT '',
    vmid        INTEGER NOT NULL DEFAULT 0,
    generation  INTEGER NOT NULL DEFAULT 0,
    metric      TEXT NOT NULL,
    value       REAL NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (remote_id, target_kind, node, vmid, generation, metric)
);
