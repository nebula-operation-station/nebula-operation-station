-- 0029_ip_entries_held.sql: mark IPAM entries taken by ipam.Store.Reserve
-- for a consumer (a guest provisioning binds the address). SetEntry never
-- overwrites a held entry; ClearEntry still releases it explicitly.
ALTER TABLE ip_entries ADD COLUMN held INTEGER NOT NULL DEFAULT 0 CHECK (held IN (0, 1));
