-- 0043_integrity_record_digests.sql
--
-- Integrity findings: the basis of an accepted or expected_pending finding
-- is compared by digest (ADR 0015 D9, ADR 0011 D6 basis rule). A record
-- longer than the stored limit, or not valid UTF-8, is stored empty; two
-- such records must not compare equal, so each record's SHA-256 digest of
-- its raw text is kept. old_digest and new_digest are the records last seen;
-- basis_old_digest and basis_new_digest are the records the human or
-- expected state was decided for, set and cleared together with the basis
-- text columns.

ALTER TABLE integrity_findings ADD COLUMN old_digest BLOB NOT NULL DEFAULT x'' CHECK (length(old_digest) IN (0, 32));
ALTER TABLE integrity_findings ADD COLUMN new_digest BLOB NOT NULL DEFAULT x'' CHECK (length(new_digest) IN (0, 32));
ALTER TABLE integrity_findings ADD COLUMN basis_old_digest BLOB CHECK (basis_old_digest IS NULL OR length(basis_old_digest) = 32);
ALTER TABLE integrity_findings ADD COLUMN basis_new_digest BLOB CHECK (basis_new_digest IS NULL OR length(basis_new_digest) = 32);
