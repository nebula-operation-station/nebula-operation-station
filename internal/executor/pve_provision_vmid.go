// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// VMID reservations (ADR 0008 section 3): a new guest's VMID is reserved
// atomically against the live cluster guest list and every other open
// provisioning of the same remote, so two proposals never bind one VMID.
// The default allocation is the next free VMID from the cluster (ADR 0008
// open question 3, draft default).

// VMID reservation limits.
const (
	// maxPveVMIDStore bounds the reservation file.
	maxPveVMIDStore = 1 << 20
	// maxPveVMIDReservations bounds the reservations in it.
	maxPveVMIDReservations = 4096
	// maxPveVMIDScan bounds the search for the next free VMID.
	maxPveVMIDScan = 100000
)

// ErrPveVMIDTaken is returned for a VMID that a live guest uses or another
// provisioning holds, and when no free VMID is found.
var ErrPveVMIDTaken = errors.New("executor: vmid is in use or reserved")

var vmidExecRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// PveVMIDReservation is one held VMID.
type PveVMIDReservation struct {
	RemoteID    string `json:"remote_id"`
	VMID        uint64 `json:"vmid"`
	ExecutionID string `json:"execution_id"`
	// ExpiresUnix ends a reservation whose provisioning never started
	// (the proposal expired or was never approved).
	ExpiresUnix int64 `json:"expires_unix"`
	// Started is set once the provisioning ran; such a reservation does
	// not expire and is released only explicitly, because the guest may
	// exist even if the run's outcome is unknown.
	Started bool `json:"started"`
	// TemplateVMID is the template the provisioning clones, recorded when
	// it starts. With VMID it is what reconciliation after a restart needs
	// to narrow a lost step to this provisioning's tasks.
	TemplateVMID uint64 `json:"template_vmid,omitempty"`
}

func (r PveVMIDReservation) live(now time.Time) bool {
	return r.Started || now.Unix() < r.ExpiresUnix
}

// PveVMIDStore keeps VMID reservations.
type PveVMIDStore interface {
	// ReserveVMID reserves want (or, when want is 0, the lowest VMID from
	// pvecontract.MinVMID up) for executionID on remoteID unless a live
	// guest (live) or another execution's reservation holds it. One
	// execution holds at most one VMID per remote; reserving again
	// replaces its reservation.
	ReserveVMID(remoteID, executionID string, want uint64, live map[uint64]bool, expires, now time.Time) (uint64, error)
	// VMIDHolder returns the reservation of vmid on remoteID that is still
	// in force at now.
	VMIDHolder(remoteID string, vmid uint64, now time.Time) (PveVMIDReservation, bool, error)
	// StartVMID marks executionID's reservation as started and records
	// the template it clones.
	StartVMID(remoteID string, vmid uint64, executionID string, templateVMID uint64) error
	// ReleaseVMID drops executionID's reservation of vmid.
	ReleaseVMID(remoteID string, vmid uint64, executionID string) error
	// Reservations returns every reservation of remoteID still in force at
	// now.
	Reservations(remoteID string, now time.Time) ([]PveVMIDReservation, error)
}

// FilePveVMIDStore keeps VMID reservations in one JSON file, written
// atomically with mode 0600. It is safe for concurrent use within one
// process; the executor is the only writer.
type FilePveVMIDStore struct {
	// Path is the reservation file, e.g. <state dir>/pve-vmids.json.
	Path string

	mu sync.Mutex
}

func (s *FilePveVMIDStore) load() ([]PveVMIDReservation, error) {
	f, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open vmid reservations: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPveVMIDStore+1))
	if err != nil {
		return nil, fmt.Errorf("read vmid reservations: %w", err)
	}
	if len(raw) > maxPveVMIDStore {
		return nil, fmt.Errorf("vmid reservations exceed %d bytes", maxPveVMIDStore)
	}
	var recs []PveVMIDReservation
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&recs); err != nil {
		return nil, fmt.Errorf("decode vmid reservations: %w", err)
	}
	if len(recs) > maxPveVMIDReservations {
		return nil, fmt.Errorf("more than %d vmid reservations", maxPveVMIDReservations)
	}
	return recs, nil
}

func (s *FilePveVMIDStore) save(recs []PveVMIDReservation) error {
	if recs == nil {
		recs = []PveVMIDReservation{}
	}
	raw, err := json.Marshal(recs)
	if err != nil {
		return fmt.Errorf("encode vmid reservations: %w", err)
	}
	if len(raw) > maxPveVMIDStore {
		return fmt.Errorf("vmid reservations exceed %d bytes", maxPveVMIDStore)
	}
	return writeFileAtomic(s.Path, raw)
}

func validVMID(v uint64) bool { return v >= pvecontract.MinVMID && v <= pvecontract.MaxVMID }

// ReserveVMID implements PveVMIDStore.
func (s *FilePveVMIDStore) ReserveVMID(remoteID, executionID string, want uint64, live map[uint64]bool, expires, now time.Time) (uint64, error) {
	if !pvecontract.ValidRemoteID(remoteID) || !vmidExecRe.MatchString(executionID) || (want != 0 && !validVMID(want)) {
		return 0, ErrPveMutationPlan
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.load()
	if err != nil {
		return 0, err
	}
	// Keep reservations in force, minus this execution's own.
	kept := recs[:0]
	held := map[uint64]bool{}
	for _, r := range recs {
		if !r.live(now) || (r.RemoteID == remoteID && r.ExecutionID == executionID && !r.Started) {
			continue
		}
		kept = append(kept, r)
		if r.RemoteID == remoteID {
			held[r.VMID] = true
		}
	}
	free := func(v uint64) bool { return !live[v] && !held[v] }
	vmid := want
	if want == 0 {
		for v, n := uint64(pvecontract.MinVMID), 0; n < maxPveVMIDScan && v <= pvecontract.MaxVMID; v, n = v+1, n+1 {
			if free(v) {
				vmid = v
				break
			}
		}
		if vmid == 0 {
			return 0, ErrPveVMIDTaken
		}
	} else if !free(want) {
		return 0, fmt.Errorf("reserve vmid %d: %w", want, ErrPveVMIDTaken)
	}
	if len(kept) >= maxPveVMIDReservations {
		return 0, fmt.Errorf("vmid reservations full (%d)", maxPveVMIDReservations)
	}
	kept = append(kept, PveVMIDReservation{RemoteID: remoteID, VMID: vmid, ExecutionID: executionID, ExpiresUnix: expires.Unix()})
	if err := s.save(kept); err != nil {
		return 0, err
	}
	return vmid, nil
}

// VMIDHolder implements PveVMIDStore.
func (s *FilePveVMIDStore) VMIDHolder(remoteID string, vmid uint64, now time.Time) (PveVMIDReservation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.load()
	if err != nil {
		return PveVMIDReservation{}, false, err
	}
	for _, r := range recs {
		if r.RemoteID == remoteID && r.VMID == vmid && r.live(now) {
			return r, true, nil
		}
	}
	return PveVMIDReservation{}, false, nil
}

// StartVMID implements PveVMIDStore.
func (s *FilePveVMIDStore) StartVMID(remoteID string, vmid uint64, executionID string, templateVMID uint64) error {
	if !validVMID(templateVMID) || templateVMID == vmid {
		return ErrPveMutationPlan
	}
	return s.update(remoteID, vmid, executionID, func(recs []PveVMIDReservation, i int) []PveVMIDReservation {
		recs[i].Started, recs[i].TemplateVMID = true, templateVMID
		return recs
	})
}

// Reservations implements PveVMIDStore.
func (s *FilePveVMIDStore) Reservations(remoteID string, now time.Time) ([]PveVMIDReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.load()
	if err != nil {
		return nil, err
	}
	var out []PveVMIDReservation
	for _, r := range recs {
		if r.RemoteID == remoteID && r.live(now) {
			out = append(out, r)
		}
	}
	return out, nil
}

// ReleaseVMID implements PveVMIDStore.
func (s *FilePveVMIDStore) ReleaseVMID(remoteID string, vmid uint64, executionID string) error {
	return s.update(remoteID, vmid, executionID, func(recs []PveVMIDReservation, i int) []PveVMIDReservation {
		return append(recs[:i], recs[i+1:]...)
	})
}

func (s *FilePveVMIDStore) update(remoteID string, vmid uint64, executionID string, f func([]PveVMIDReservation, int) []PveVMIDReservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.load()
	if err != nil {
		return err
	}
	for i, r := range recs {
		if r.RemoteID == remoteID && r.VMID == vmid {
			if r.ExecutionID != executionID {
				return fmt.Errorf("vmid %d: %w", vmid, ErrPveVMIDTaken)
			}
			return s.save(f(recs, i))
		}
	}
	return fmt.Errorf("vmid %d: no reservation: %w", vmid, ErrPveVMIDTaken)
}
