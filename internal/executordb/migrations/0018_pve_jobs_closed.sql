-- 0018_pve_jobs_closed.sql (ADR 0008 PV-01 follow-up): an admin may close
-- the open steps of a PVE remote that is removed, or blocked and not
-- re-pinned, because reconciliation has no pinned identity to observe them
-- through. Such a step becomes 'unknown' (its task's outcome was never
-- observed). closed_by and closed_reason record who closed it and why;
-- both are NULL for a step that reached its state by reconciliation.
ALTER TABLE pve_jobs ADD COLUMN closed_by TEXT
    CHECK (closed_by IS NULL OR length(closed_by) BETWEEN 1 AND 64);
ALTER TABLE pve_jobs ADD COLUMN closed_reason TEXT
    CHECK (closed_reason IS NULL OR length(closed_reason) BETWEEN 1 AND 256);
