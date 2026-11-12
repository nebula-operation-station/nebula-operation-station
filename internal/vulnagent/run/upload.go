// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Batch packing bounds (A1.3).
const (
	// MaxRecordBytes bounds one encoded record with its separator.
	MaxRecordBytes = 16 << 10
	// BatchEnvelopeMaxBytes is reserved in each batch for the envelope.
	BatchEnvelopeMaxBytes = 16 << 10
)

// encodeRecord encodes a record as sent: compact, without HTML escaping.
func encodeRecord(rec vulnfinding.Record) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return nil, fmt.Errorf("encode record: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// printRecords is the dry run's phase 5: every record exactly as it
// would be sent, one JSON object per line, and no NOS write.
func (r *Runner) printRecords(m *matched, rep *Report) error {
	for _, p := range m.findings {
		b, err := encodeRecord(p.rec)
		if err != nil {
			return err
		}
		if _, err := r.cfg.Out.Write(append(b, '\n')); err != nil {
			return fmt.Errorf("print records: %w", err)
		}
		rep.Printed++
	}
	r.log.Info("dry run: records printed, nothing submitted", "records", rep.Printed)
	return nil
}

// packer fills batches up to the D5 count and byte limits.
type packer struct {
	batches []nosclient.Batch
	cur     nosclient.Batch
	size    int
}

func (p *packer) flush() {
	if len(p.cur.Findings) == 0 && len(p.cur.Subjects) == 0 {
		return
	}
	p.cur.Seq = int64(len(p.batches) + 1)
	p.batches = append(p.batches, p.cur)
	p.cur, p.size = nosclient.Batch{}, 0
}

func (p *packer) addFinding(b []byte) {
	if len(p.cur.Findings) >= nosclient.MaxFindingsPerBatch ||
		p.size+len(b)+1 > nosclient.MaxBatchBytes-BatchEnvelopeMaxBytes {
		p.flush()
	}
	p.cur.Findings = append(p.cur.Findings, json.RawMessage(b))
	p.size += len(b) + 1
}

func (p *packer) addSubject(s nosclient.BatchSubject) error {
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode subject: %w", err)
	}
	if len(p.cur.Subjects) >= nosclient.MaxCoveredPerBatch ||
		p.size+len(b)+1 > nosclient.MaxBatchBytes-BatchEnvelopeMaxBytes {
		p.flush()
	}
	p.cur.Subjects = append(p.cur.Subjects, s)
	p.size += len(b) + 1
	return nil
}

// pack builds the batches: per subject in export order its records, then,
// if the run covered the subject completely, every part of it as covered.
// A record over MaxRecordBytes is sent without its assessment text; one
// still over the bound is withheld and its subject is not named.
func pack(snap *nosclient.Snapshot, m *matched) ([]nosclient.Batch, int, int, error) {
	bySubject := map[string][]prepared{}
	for _, f := range m.findings {
		bySubject[f.subject] = append(bySubject[f.subject], f)
	}
	var p packer
	withheld, covered := 0, 0
	for _, cov := range snap.Subjects {
		key := subjectKey(cov.Kind, cov.Ref)
		ok := cov.Complete && !m.uncovered[key]
		for _, f := range bySubject[key] {
			b, err := encodeRecord(f.rec)
			if err != nil {
				return nil, 0, 0, err
			}
			if len(b)+1 > MaxRecordBytes {
				f.rec.Assessment = vulnfinding.Assessment{}
				if b, err = encodeRecord(f.rec); err != nil {
					return nil, 0, 0, err
				}
			}
			if len(b)+1 > MaxRecordBytes {
				withheld++
				ok = false
				continue
			}
			p.addFinding(b)
		}
		delete(bySubject, key)
		if !ok {
			continue
		}
		for _, s := range cov.BatchSubjects() {
			if err := p.addSubject(s); err != nil {
				return nil, 0, 0, err
			}
		}
		covered++
	}
	// Records of subjects the snapshot does not hold cannot be sent.
	for _, fs := range bySubject {
		withheld += len(fs)
	}
	p.flush()
	return p.batches, withheld, covered, nil
}

// upload is run order phase 5: start, batches, complete, bounded by
// UploadPhaseMax. Out of time, no complete is sent.
func (r *Runner) upload(ctx context.Context, snap *nosclient.Snapshot, m *matched, rep *Report) error {
	batches, withheld, covered, err := pack(snap, m)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUpload, err)
	}
	rep.Withheld += withheld
	if len(m.sources) == 0 {
		return ErrNoFeeds
	}
	uctx, cancel := context.WithTimeout(ctx, UploadPhaseMax)
	defer cancel()
	run, err := r.cfg.NOS.StartRun(uctx, snap, startRequest(m.sources, m.loaded, m.version))
	if err != nil {
		return fmt.Errorf("%w: start: %w", ErrUpload, err)
	}
	rep.RunID = run.ID
	for _, s := range run.Sources {
		if s.Status != "accepted" || s.Stale || s.Probation {
			r.log.Warn("source verdict", "source", s.SourceID, "status", cleanText(s.Status, 32), "stale", s.Stale, "probation", s.Probation)
		}
	}
	r.log.Info("run started on NOS", "run_id", run.ID, "run_seq", run.Seq, "batches", len(batches),
		"unknown_sources", run.UnknownCount)
	for _, b := range batches {
		res, err := run.Submit(uctx, b)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUpload, err)
		}
		rep.Batches++
		rep.Rejected += res.Rejected
		for _, rj := range res.Rejections {
			r.log.Warn("record rejected by NOS", "run_id", run.ID, "batch", b.Seq, "index", rj.Index,
				"finding_key", cleanText(rj.Key, 64), "reason", cleanText(rj.Reason, maxEvidenceText))
		}
	}
	if uctx.Err() != nil {
		return fmt.Errorf("%w: upload phase over: %w", ErrUpload, uctx.Err())
	}
	cr, err := run.Complete(uctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUpload, err)
	}
	rep.SubjectsCovered = covered
	rep.Completion = cr.Completion
	r.log.Info("run completed on NOS", "run_id", run.ID, "repeat", cr.Repeat,
		"closed_evidenced", cr.Completion.ClosedEvidenced, "closed_unconfirmed", cr.Completion.ClosedUnconfirmed,
		"run_guard", cr.Completion.RunGuard, "window_guard", cr.Completion.WindowGuard)
	return nil
}
