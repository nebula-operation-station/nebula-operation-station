-- 0054_vuln_image_read_once.sql
-- One stored image read per execution and host (follow-up to #832, iv12).
-- A retried or replayed store of one image.packages grant used to insert the
-- same read again; copies then filled the ImageReadsKept budget of 0053 and
-- pushed out real reads. Now the table holds at most one read of one
-- execution on one host, and PutImage (internal/vulninventory, images.go)
-- inserts with ON CONFLICT DO NOTHING.
--
-- Step 1 removes copies that 0053 already stored: of each (host_id,
-- execution_id) only the newest row (highest id) is kept. Reads are immutable
-- (trigger in 0053), so this delete is the only change to existing rows.
DELETE FROM vuln_image_reads WHERE id NOT IN (
    SELECT max(id) FROM vuln_image_reads GROUP BY host_id, execution_id
);

-- Step 2: the one-read-per-execution key.
CREATE UNIQUE INDEX vuln_image_reads_host_execution ON vuln_image_reads (host_id, execution_id);

-- Step 3: the docker.inspect lookup of ObserveImage (cmd/nebula-server,
-- vuln_images.go). It filters execution_hosts by host, state, class and
-- finished_at, and takes the newest rows first. Without this index the
-- lookup walked every stored execution of the host through the action index.
-- The query is pinned to this index by a plan test in cmd/nebula-server.
CREATE INDEX execution_hosts_inspect ON execution_hosts (host_id, state, class, finished_at);
