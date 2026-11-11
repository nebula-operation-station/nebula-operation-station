-- 0039_netdev_carried_index.sql
-- Index the carried rows of the network device inventory (ADR 0010 Q11;
-- plan ND-16 part 1).
--
-- Every ReplaceDataset, including an unchanged poll, removes rows carried
-- over with a seen_at before the retention window from every kept dataset
-- of the (device, read) (internal/netdevinventory dropExpiredCarried):
--
--   DELETE FROM <row table> WHERE seen_at IS NOT NULL AND seen_at < ?
--     AND dataset_id IN (SELECT id FROM netdev_datasets WHERE read = ? ...)
--
-- Without an index on seen_at that walks every row of every kept dataset
-- through the (dataset_id, row_key) primary key. The partial index below
-- holds only carried rows (present rows have seen_at NULL) and turns the
-- delete into a range search per dataset that visits only expired rows.

CREATE INDEX idx_netdev_facts_carried ON netdev_facts (dataset_id, seen_at) WHERE seen_at IS NOT NULL;
CREATE INDEX idx_netdev_vlans_carried ON netdev_vlans (dataset_id, seen_at) WHERE seen_at IS NOT NULL;
CREATE INDEX idx_netdev_interfaces_carried ON netdev_interfaces (dataset_id, seen_at) WHERE seen_at IS NOT NULL;
CREATE INDEX idx_netdev_mac_entries_carried ON netdev_mac_entries (dataset_id, seen_at) WHERE seen_at IS NOT NULL;
CREATE INDEX idx_netdev_lldp_neighbors_carried ON netdev_lldp_neighbors (dataset_id, seen_at) WHERE seen_at IS NOT NULL;
CREATE INDEX idx_netdev_fw_rules_carried ON netdev_fw_rules (dataset_id, seen_at) WHERE seen_at IS NOT NULL;
CREATE INDEX idx_netdev_nat_rules_carried ON netdev_nat_rules (dataset_id, seen_at) WHERE seen_at IS NOT NULL;
CREATE INDEX idx_netdev_objects_carried ON netdev_objects (dataset_id, seen_at) WHERE seen_at IS NOT NULL;
CREATE INDEX idx_netdev_rule_hits_carried ON netdev_rule_hits (dataset_id, seen_at) WHERE seen_at IS NOT NULL;
