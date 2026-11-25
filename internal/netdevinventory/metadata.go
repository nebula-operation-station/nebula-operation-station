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
// reason without a block. The message never quotes the record.
var ErrInvalidMetadata = errors.New("netdevinventory: device metadata is invalid")

// ErrBlockedDevice is returned for a metadata record of a blocked device.
// The row has no field for the block, so a blocked device is refused and
// nothing is written.
var ErrBlockedDevice = errors.New("netdevinventory: device is blocked")

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
// family, label, trust generation and the spool reference, and never an
// endpoint or a pin, because the record has none. The row is marked
// OriginCollectorReported. That is a collector report, not an admin
// confirmation, and a row without endpoints or pin is never usable for a
// connection.
//
// The record is checked here before the shared row rules apply: the family
// must be known, the device ID well formed, the label bounded printable
// UTF-8, the trust generation in range, and a blocked device is refused with
// ErrBlockedDevice. The shared rules then refuse a family change, a lower
// trust generation and, at the same generation, a record that is not
// strictly newer than the stored one. A refusal writes nothing. A blocked
// record leaves the stored row as it is, so the device list shows no block:
// the caller that receives ErrBlockedDevice must surface the block itself.
func (s *Store) UpsertDeviceMetadata(ctx context.Context, m DeviceMetadataRecord, ref SpoolRef) error {
	if err := ref.validate(); err != nil {
		return fmt.Errorf("netdevinventory: upsert device metadata: %w", err)
	}
	if err := validateMetadata(m); err != nil {
		return fmt.Errorf("netdevinventory: upsert device metadata: %w", err)
	}
	return s.writeDeviceRow(ctx, deviceRow{id: m.DeviceID, family: m.Family, label: m.Label,
		gen: m.TrustGeneration}, ref)
}

// validateMetadata checks one metadata record. It returns ErrBlockedDevice for
// a blocked device and wraps ErrInvalidMetadata for every other refusal.
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
	if m.Blocked {
		return ErrBlockedDevice
	}
	if m.BlockReason != "" {
		return fmt.Errorf("block reason without a block: %w", ErrInvalidMetadata)
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

// printableText is netdevcontract's printable rule for untrusted text: the
// rune is accepted by unicode.IsPrint and is not U+FFFD. It rejects controls,
// format characters (bidi overrides, isolates, zero-width characters), the
// line and paragraph separators U+2028 and U+2029, private use, surrogates,
// unassigned code points and every space except U+0020.
func printableText(r rune) bool {
	return r != utf8.RuneError && unicode.IsPrint(r)
}
