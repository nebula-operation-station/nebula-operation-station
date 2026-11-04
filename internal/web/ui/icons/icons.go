// SPDX-License-Identifier: AGPL-3.0-or-later

// Package icons is the server side of the icon pipeline (ADR 0009 D6,
// TM16): it queues fetch jobs for the nebula-iconfetch helper, imports
// the helper's results, accepts admin uploads, rolls icons back and serves
// stored icons as /icons/<sha256>.png.
//
// Every image the server stores went through internal/iconstore.Sanitize
// in this process: uploads directly, fetched icons a second time after
// the helper (the helper is the process that touches hostile bytes; the
// server does not trust its output). Every change is audited twice: in the
// catalog's audit table (softwarecat) and as an "audit" log event.
package icons

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/iconfetch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons/iconjob"
)

// MaxImportPerRun bounds how many results one ImportResults call handles.
const MaxImportPerRun = 64

// Errors callers branch on.
var (
	// ErrUnavailable means the icon spool is not installed.
	ErrUnavailable = errors.New("icons: icon fetcher is not installed")
	// ErrRejected means the admin input (key, URL or image) was refused.
	ErrRejected = errors.New("icons: rejected")
)

// Config configures a Service.
type Config struct {
	// Spool is the nebula-iconfetch spool.
	Spool iconjob.Spool
	// Store is the content-addressed icon store.
	Store *iconstore.Store
	// Catalog records icons, icon history and the catalog audit trail.
	Catalog *softwarecat.Store
	// Allow is the icon host allowlist; empty means
	// iconfetch.DefaultAllowlist().
	Allow []string
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
	// Log receives the audit events; nil discards them.
	Log *slog.Logger
}

// Service is the server side of the icon pipeline.
type Service struct {
	spool   iconjob.Spool
	store   *iconstore.Store
	catalog *softwarecat.Store
	allow   []string
	now     func() time.Time
	log     *slog.Logger
}

// New returns a Service.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.Catalog == nil {
		return nil, errors.New("icons: icon store and catalog are required")
	}
	s := &Service{spool: cfg.Spool, store: cfg.Store, catalog: cfg.Catalog,
		allow: append([]string(nil), cfg.Allow...), now: cfg.Now, log: cfg.Log}
	if len(s.allow) == 0 {
		s.allow = iconfetch.DefaultAllowlist()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	return s, nil
}

// audit logs one audit event in the same form as the other web handlers.
func (s *Service) audit(ctx context.Context, kind, actor string, attrs ...any) {
	s.log.InfoContext(ctx, "audit", append([]any{"kind", kind, "user", actor}, attrs...)...)
}

// catalogKey validates a catalog key and checks that the entry exists and
// was not merged into another key.
func (s *Service) catalogKey(ctx context.Context, key string) (softwarecat.Key, error) {
	k, err := softwarecat.NewKey(key)
	if err != nil {
		return "", fmt.Errorf("%w: catalog key: %w", ErrRejected, err)
	}
	e, err := s.catalog.Entry(ctx, k)
	if err != nil {
		if errors.Is(err, softwarecat.ErrNotFound) {
			return "", fmt.Errorf("%w: catalog key %s: %w", ErrRejected, k, err)
		}
		return "", fmt.Errorf("read catalog entry %s: %w", k, err)
	}
	if e.MergedInto != "" {
		return "", fmt.Errorf("%w: catalog key %s was merged into %s", ErrRejected, k, e.MergedInto)
	}
	return k, nil
}

// QueueFetch validates key and rawURL (iconfetch URL policy) and queues a
// job for the helper. It returns the job ID. The fetched icon is set on
// the key when ImportResults picks up the helper's result.
func (s *Service) QueueFetch(ctx context.Context, actor, key, rawURL string) (string, error) {
	if !s.spool.Available() {
		return "", ErrUnavailable
	}
	k, err := s.catalogKey(ctx, key)
	if err != nil {
		s.audit(ctx, "icon_fetch_rejected", actor, "key", key, "error", err.Error())
		return "", err
	}
	u, err := iconfetch.ValidateURL(rawURL, s.allow)
	if err != nil {
		s.audit(ctx, "icon_fetch_rejected", actor, "key", string(k), "error", err.Error())
		return "", fmt.Errorf("%w: %w", ErrRejected, err)
	}
	id, err := iconjob.NewID()
	if err != nil {
		return "", err
	}
	j := iconjob.Job{Format: iconjob.JobFormat, ID: id, Key: string(k), URL: u.String(), RequestedBy: actor, CreatedAt: s.now().Unix()}
	if err := s.spool.WriteJob(j); err != nil {
		if errors.Is(err, iconjob.ErrInvalid) {
			s.audit(ctx, "icon_fetch_rejected", actor, "key", string(k), "error", err.Error())
			return "", fmt.Errorf("%w: %w", ErrRejected, err)
		}
		return "", fmt.Errorf("queue icon fetch for %s: %w", k, err)
	}
	s.audit(ctx, "icon_fetch_queued", actor, "job", id, "key", string(k), "url", j.URL)
	return id, nil
}

// ImportReport summarizes one ImportResults call.
type ImportReport struct {
	// Imported maps job IDs to the stored icon hash.
	Imported map[string]string
	// Failed maps job IDs to the reason the job produced no icon.
	Failed map[string]string
}

// permanent reports whether an import error will not go away on retry.
func permanent(err error) bool {
	for _, e := range []error{ErrRejected, iconjob.ErrInvalid, softwarecat.ErrInvalidInput, softwarecat.ErrNotFound,
		softwarecat.ErrMerged, softwarecat.ErrInvalidKey} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// ImportResults imports the helper's results: each successful icon is
// sanitized again, stored, registered with its source URL and set on the
// job's catalog key. Failed and invalid results are audited. A job is
// removed from the spool once handled; a transient error (database, disk)
// leaves it for the next call and is returned.
//
// The server never writes results/ (only the helper prunes it, after a
// day); removing the job file is what marks a result as handled.
// FinishedJobs skips results without a job file before MaxImportPerRun
// is applied, so old, already imported results never crowd out new ones.
func (s *Service) ImportResults(ctx context.Context) (ImportReport, error) {
	rep := ImportReport{Imported: map[string]string{}, Failed: map[string]string{}}
	ids, err := s.spool.FinishedJobs()
	if err != nil {
		return rep, err
	}
	if len(ids) > MaxImportPerRun {
		ids = ids[:MaxImportPerRun]
	}
	var errs []error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		j, err := s.spool.ReadJob(id)
		if errors.Is(err, os.ErrNotExist) {
			continue // removed since the listing (imported or cancelled); the helper prunes the result
		}
		if err != nil {
			// A job file the server cannot read back is not trusted for
			// key, URL or actor; drop it.
			s.audit(ctx, "icon_fetch_failed", "nebula-server", "job", id, "error", err.Error())
			rep.Failed[id] = err.Error()
			if err := s.spool.RemoveJob(id); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		sha, err := s.importOne(ctx, j)
		if err != nil && !permanent(err) {
			errs = append(errs, fmt.Errorf("import icon job %s: %w", id, err))
			continue
		}
		if err != nil {
			s.audit(ctx, "icon_fetch_failed", j.RequestedBy, "job", id, "key", j.Key, "url", j.URL, "error", err.Error())
			rep.Failed[id] = err.Error()
		} else {
			s.audit(ctx, "icon_fetch_imported", j.RequestedBy, "job", id, "key", j.Key, "url", j.URL, "sha256", sha)
			rep.Imported[id] = sha
		}
		if err := s.spool.RemoveJob(id); err != nil {
			errs = append(errs, err)
		}
	}
	return rep, errors.Join(errs...)
}

// importOne imports the result of job j.
func (s *Service) importOne(ctx context.Context, j iconjob.Job) (string, error) {
	res, err := s.spool.ReadResult(j.ID)
	if err != nil {
		if errors.Is(err, iconjob.ErrInvalid) {
			return "", fmt.Errorf("invalid helper result: %w", err)
		}
		return "", err
	}
	if !res.OK {
		return "", fmt.Errorf("%w: fetch failed: %s", ErrRejected, res.Error)
	}
	// Defence in depth: the server re-validates the URL and re-sanitizes
	// the bytes; the stored icon is always this process's own encoding.
	if _, err := iconfetch.ValidateURL(j.URL, s.allow); err != nil {
		return "", fmt.Errorf("%w: %w", ErrRejected, err)
	}
	subject := softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: j.Key}
	return s.storeAndSet(ctx, j.RequestedBy, subject, res.PNG128, softwarecat.IconURL, j.URL)
}

// storeAndSet sanitizes data, stores it, registers it and sets it on
// subject. It returns the icon hash.
func (s *Service) storeAndSet(ctx context.Context, actor string, subject softwarecat.IconSubject, data []byte,
	kind softwarecat.IconSourceKind, sourceURL string) (string, error) {
	ic, err := iconstore.Sanitize(data)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrRejected, err)
	}
	if err := s.store.Put(ctx, ic); err != nil {
		return "", err
	}
	if _, err := s.catalog.RegisterIcon(ctx, actor, ic.SHA256, kind, sourceURL); err != nil {
		return "", err
	}
	if err := s.catalog.SetIcon(ctx, actor, subject, ic.SHA256); err != nil {
		return "", err
	}
	return ic.SHA256, nil
}

// Upload sanitizes an admin-uploaded image (PNG, JPEG or GIF, at most
// iconstore.MaxInputBytes), stores it and sets it on subject (a catalog
// key or an asset override). It returns the icon hash.
func (s *Service) Upload(ctx context.Context, actor string, subject softwarecat.IconSubject, data []byte) (string, error) {
	if subject.Kind == softwarecat.SubjectCatalog {
		if _, err := s.catalogKey(ctx, subject.ID); err != nil {
			s.audit(ctx, "icon_upload_rejected", actor, "subject_kind", string(subject.Kind), "subject", subject.ID, "error", err.Error())
			return "", err
		}
	}
	sha, err := s.storeAndSet(ctx, actor, subject, data, softwarecat.IconUpload, "")
	if err != nil {
		s.audit(ctx, "icon_upload_rejected", actor, "subject_kind", string(subject.Kind), "subject", subject.ID, "bytes", len(data), "error", err.Error())
		if permanent(err) && !errors.Is(err, ErrRejected) {
			err = fmt.Errorf("%w: %w", ErrRejected, err)
		}
		return "", err
	}
	s.audit(ctx, "icon_uploaded", actor, "subject_kind", string(subject.Kind), "subject", subject.ID, "bytes", len(data), "sha256", sha)
	return sha, nil
}

// Rollback undoes icon change changeID of subject (one-click rollback to
// the previous hash; see softwarecat.Store.RollbackIcon).
func (s *Service) Rollback(ctx context.Context, actor string, subject softwarecat.IconSubject, changeID int64) error {
	if err := s.catalog.RollbackIcon(ctx, actor, subject, changeID); err != nil {
		s.audit(ctx, "icon_rollback_rejected", actor, "subject_kind", string(subject.Kind), "subject", subject.ID, "change", changeID, "error", err.Error())
		if permanent(err) {
			return fmt.Errorf("%w: %w", ErrRejected, err)
		}
		return err
	}
	attrs := []any{"subject_kind", string(subject.Kind), "subject", subject.ID, "change", changeID}
	// The rollback appended the newest history entry: it names the icon
	// that was put back and the one it replaced ("" is the generic
	// symbol). The lookup is for the log only; the rollback is done.
	if h, err := s.catalog.IconHistory(ctx, subject, 1); err == nil && len(h) == 1 && h[0].RollbackOf == changeID {
		attrs = append(attrs, "sha256", h[0].SHA, "replaced_sha256", h[0].PrevSHA)
	} else {
		attrs = append(attrs, "sha256", "unknown")
	}
	s.audit(ctx, "icon_rolled_back", actor, attrs...)
	return nil
}
