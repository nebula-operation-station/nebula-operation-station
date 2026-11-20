-- 0051_execution_reject_intent.sql (spec 07 v29-07-01, "Server crash between
-- RejectPending and its update"): the server stores a rejection intent in the
-- pending execution record before it calls RejectPending. The intent is the
-- user of the privileged session, the reason text and the time. It is server
-- data only: it does not change the state and has no effect on authority.
--
-- All three columns are nullable and have no default: no intent means NULL.
-- The reason keeps the UI limit of 200 characters. Adding nullable columns
-- needs no table rebuild, so the rows and the CHECK on state stay as they are.

ALTER TABLE executions ADD COLUMN reject_user TEXT CHECK (reject_user IS NULL OR length(reject_user) <= 64);
ALTER TABLE executions ADD COLUMN reject_reason TEXT CHECK (reject_reason IS NULL OR length(reject_reason) <= 200);
ALTER TABLE executions ADD COLUMN reject_at INTEGER;
