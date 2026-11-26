// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// ErrInvalidMetadata is returned for a device metadata record the writer
// refuses: an unknown family, a malformed device ID, a label that is not
// bounded printable UTF-8, a trust generation out of range, or a block
// reason without a block, or a block reason that is not bounded printable
// UTF-8. The message never quotes the record.
var ErrInvalidMetadata = errors.New("netdevinventory: device metadata is invalid")

// MaxBlockReasonBytes bounds the block reason the collector reports, as
// migration 0059 does for netdev_devices_seen.block_reason.
const MaxBlockReasonBytes = 256

// MaxBlockedDevices bounds how many blocked device IDs BlockedDeviceIDs
// returns. More blocked rows than this is an error, never a short list.
const MaxBlockedDevices = MaxListDevices

// DeviceMetadataRecord is the registry metadata of one device as the
// collector spooled it (ADR 0010 D1): the fields the device list shows. It
// carries no endpoint, no trust pin and no device data.
type DeviceMetadataRecord struct {
	DeviceID        string
	Family          netdevcontract.Family
	Label           string
	TrustGeneration uint64
	Blocked         bool
	BlockReason     string
}

// UpsertDeviceMetadata writes the device row of one metadata record, named by
// the spool record ref. It is the metadata-only writer: it writes device_id,
// family, label, trust generation, the block state and the spool reference,
// and never an endpoint or a pin, because the record has none. The row is marked
// OriginCollectorReported. That is a collector report, not an admin
// confirmation, and a row without endpoints or pin is never usable for a
// connection.
//
// The record is checked here before the shared row rules apply: the family
// must be known, the device ID well formed, the label bounded printable
// UTF-8, the trust generation in range, and the block reason bounded
// printable UTF-8 and only present on a blocked record. The shared rules then
// refuse a family change, a lower trust generation and, at the same
// generation, a record that is not strictly newer than the stored one. A
// refusal writes nothing.
//
// A blocked record is written like any other and sets the row's block state
// (blocked, block_reason); a newer unblocked record clears it. The device
// list shows the block from the row, and the importer reads it back with
// BlockedDeviceIDs (before, ErrBlockedDevice refused the record and the row
// showed no block).
func (s *Store) UpsertDeviceMetadata(ctx context.Context, m DeviceMetadataRecord, ref SpoolRef) error {
	if err := ref.validate(); err != nil {
		return fmt.Errorf("netdevinventory: upsert device metadata: %w", err)
	}
	if err := validateMetadata(m); err != nil {
		return fmt.Errorf("netdevinventory: upsert device metadata: %w", err)
	}
	return s.writeDeviceRow(ctx, deviceRow{id: m.DeviceID, family: m.Family, label: m.Label,
		gen: m.TrustGeneration, setBlock: true, blocked: m.Blocked, blockReason: m.BlockReason}, ref)
}

// BlockedDeviceIDs returns the IDs of the devices whose row is blocked, in
// device ID order. It returns an error instead of a partial list when more
// than MaxBlockedDevices rows are blocked, so a caller never treats a blocked
// device as unblocked.
func (s *Store) BlockedDeviceIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device_id FROM netdev_devices_seen
		WHERE blocked = 1 ORDER BY device_id LIMIT ?`, MaxBlockedDevices+1)
	if err != nil {
		return nil, fmt.Errorf("netdevinventory: list blocked devices: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("netdevinventory: list blocked devices: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("netdevinventory: list blocked devices: %w", err)
	}
	if len(ids) > MaxBlockedDevices {
		return nil, fmt.Errorf("netdevinventory: list blocked devices: more than %d", MaxBlockedDevices)
	}
	return ids, nil
}

// validateMetadata checks one metadata record. Every refusal wraps
// ErrInvalidMetadata.
func validateMetadata(m DeviceMetadataRecord) error {
	if !netdevcontract.ValidDeviceID(m.DeviceID) {
		return fmt.Errorf("device id is malformed: %w", ErrInvalidMetadata)
	}
	switch m.Family {
	case netdevcontract.FamilyCBS, netdevcontract.FamilyPANOS:
	default:
		return fmt.Errorf("family is unknown: %w", ErrInvalidMetadata)
	}
	if !validLabel(m.Label) {
		return fmt.Errorf("label is not printable UTF-8 of at most %d bytes: %w",
			netdevcontract.MaxLabelBytes, ErrInvalidMetadata)
	}
	if m.TrustGeneration == 0 || m.TrustGeneration > netdevcontract.MaxTrustGeneration {
		return fmt.Errorf("trust generation outside 1..%d: %w", netdevcontract.MaxTrustGeneration, ErrInvalidMetadata)
	}
	if !m.Blocked && m.BlockReason != "" {
		return fmt.Errorf("block reason without a block: %w", ErrInvalidMetadata)
	}
	if !validBlockReason(m.BlockReason) {
		return fmt.Errorf("block reason is not printable UTF-8 of at most %d bytes: %w",
			MaxBlockReasonBytes, ErrInvalidMetadata)
	}
	return nil
}

// validLabel reports whether s is a label of at most netdevcontract.MaxLabelBytes
// bytes, valid UTF-8, in which every rune is printable under the spec 09 rule
// that netdevcontract applies to the same column in UpsertDeviceReported. That
// rule is unexported in netdevcontract, so it is repeated here exactly, and
// TestValidLabelMatchesContractText checks the two against each other. An
// empty label is allowed: the row default is empty.
func validLabel(s string) bool {
	if len(s) > netdevcontract.MaxLabelBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !printableText(r) {
			return false
		}
	}
	return true
}

// validBlockReason reports whether s is a block reason of at most
// MaxBlockReasonBytes bytes of printable UTF-8 under the same rune rule as
// validLabel. An empty reason is allowed.
func validBlockReason(s string) bool {
	if len(s) > MaxBlockReasonBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !printableText(r) {
			return false
		}
	}
	return true
}

// printableText is netdevcontract's printable rule for untrusted text: the
// rune is accepted by unicode.IsPrint and is not U+FFFD. It rejects controls,
// format characters (bidi overrides, isolates, zero-width characters), the
// line and paragraph separators U+2028 and U+2029, private use, surrogates,
// unassigned code points and every space except U+0020.
func printableText(r rune) bool {
	return r != utf8.RuneError && unicode.IsPrint(r)
}
