-- 0023_container_recreation_hold_end.sql (ADR 0006 P2-04/05, cu03s): when
-- the batch hold of a row's target last ended, as Unix seconds; 0 means
-- unknown (no hold end recorded, for example a row from before this
-- migration). A resolve accepts only a preview that started after it, so
-- an unknown hold end refuses every resolve of the row (fail closed).
ALTER TABLE container_recreations ADD COLUMN hold_ended_at INTEGER NOT NULL DEFAULT 0 CHECK (hold_ended_at >= 0);
