// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Image read leases (ADR 0011, amendment 2026-11-23). An image read needs a
// read lease that pins one container (docker.inspect) and one digest-pinned
// image (image.packages). The page offers only pairs that a recent,
// successful docker.inspect of the host names, so a lease is never proposed
// for an image the host does not run. The executor checks the parameters
// hash, the artifact and the LOW risk class on every run; this file only
// builds the proposal and keeps the plain-text parameters for the page.

// Limits and fixed values of image read leases.
const (
	// ImageLeaseInterval is the minimum interval between two runs of an
	// image lease, and the lease's rate.
	ImageLeaseInterval = 24 * time.Hour
	// ImageLeaseRunBudget is the rolling-hour run budget of an image lease.
	ImageLeaseRunBudget = 2
	// ImageLeaseInspectMaxAge is how old a docker.inspect result may be and
	// still name an image for a proposal.
	ImageLeaseInspectMaxAge = 24 * time.Hour
	// maxImageLeaseOptions bounds the (container, image) pairs offered.
	maxImageLeaseOptions = 200
	// maxImageLeaseInspectRows bounds the stored inspect results read.
	maxImageLeaseInspectRows = 500
)

// The two actions of an image lease.
const (
	imageLeaseInspectAction = "docker.inspect"
	imageLeaseImageAction   = "image.packages"
)

// ErrImageLeaseHost is the fixed reason for a host an image lease cannot
// name: not enrolled, blocked, without a valid host key pin or credential.
var ErrImageLeaseHost = &ReadGrantInputError{"the host cannot be leased: it is not enrolled, is blocked or has no valid host key pin or credential"}

// ImageLeaseOption is one (container, image) pair a recent docker.inspect of
// a host names. Image is a digest-pinned reference (repository@sha256:...).
type ImageLeaseOption struct {
	Container string
	Image     string
}

// ImageReadGrantRequest is what the image lease form submits.
type ImageReadGrantRequest struct {
	HostID    string
	Container string
	Image     string
	Days      int // ReadGrantShortDays or ReadGrantLongDays
}

// ImageLeaseOptions returns the distinct (container, image) pairs that the
// successful docker.inspect results of host, finished at most
// ImageLeaseInspectMaxAge ago, name, newest first. A result that does not
// parse, is not a finished inspect or names no valid image is skipped.
func (s *Service) ImageLeaseOptions(ctx context.Context, hostID string) ([]ImageLeaseOption, error) {
	if s.db == nil {
		return nil, errors.New("image lease options: no database")
	}
	now := s.now()
	rows, err := s.db.QueryContext(ctx, imageLeaseInspectQuery, hostID,
		now.Add(-ImageLeaseInspectMaxAge).Unix(), now.Unix(), imageLeaseInspectAction, hostrun.MaxResult, maxImageLeaseInspectRows)
	if err != nil {
		return nil, fmt.Errorf("image lease options: %w", err)
	}
	defer rows.Close()
	var out []ImageLeaseOption
	seen := map[ImageLeaseOption]bool{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("image lease options: %w", err)
		}
		in, err := dockerhost.ParseInspect(raw)
		if err != nil || in.Phase != "done" || in.Container == "" || validInspectContainer(in.Container) != nil {
			continue
		}
		for _, d := range in.Digests {
			if validImageLeaseImage(d) != nil {
				continue
			}
			o := ImageLeaseOption{Container: in.Container, Image: d}
			if seen[o] {
				continue
			}
			seen[o] = true
			out = append(out, o)
			if len(out) == maxImageLeaseOptions {
				return out, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("image lease options: %w", err)
	}
	return out, nil
}

// imageLeaseInspectQuery selects the successful docker.inspect results of one
// host that finished in a window, newest first. It keeps the join shape of
// the server's inspect lookup (execution_hosts outer, CROSS JOIN) so the
// execution_hosts_inspect index is used.
const imageLeaseInspectQuery = `SELECT h.result FROM execution_hosts h CROSS JOIN executions e
	WHERE h.host_id = ? AND h.state = 'finished' AND h.class = 'success'
	AND h.finished_at >= ? AND h.finished_at <= ?
	AND e.id = h.execution_id AND e.action_id = ? AND length(h.result) <= ?
	ORDER BY h.finished_at DESC, e.id DESC LIMIT ?`

// validInspectContainer checks the docker.inspect container parameter.
func validInspectContainer(c string) error {
	a, ok := actions.Lookup(imageLeaseInspectAction)
	if !ok {
		return errors.New("docker.inspect is not an action")
	}
	return a.ValidParams(map[string]string{"container": c})
}

// validImageLeaseImage checks the image.packages image parameter.
func validImageLeaseImage(ref string) error {
	a, ok := actions.Lookup(imageLeaseImageAction)
	if !ok {
		return errors.New("image.packages is not an action")
	}
	return a.ValidParams(map[string]string{"image": ref})
}

// imageLeaseParams returns the plain-text parameters of the two actions of an
// image lease for one request, in the order the document lists them.
func imageLeaseParams(in ImageReadGrantRequest) []imageLeaseAction {
	return []imageLeaseAction{
		{ID: imageLeaseInspectAction, Params: map[string]string{"container": in.Container}},
		{ID: imageLeaseImageAction, Params: map[string]string{"image": in.Image}},
	}
}

// imageLeaseAction is one action of an image lease with its parameters.
type imageLeaseAction struct {
	ID     string
	Params map[string]string
}

// checkImageReadGrantRequest validates the image lease form input. Its errors
// are fixed texts that never echo the input.
func checkImageReadGrantRequest(in ImageReadGrantRequest) error {
	if in.Days != ReadGrantShortDays && in.Days != ReadGrantLongDays {
		return &ReadGrantInputError{fmt.Sprintf("a read lease lasts %d or %d days", ReadGrantShortDays, ReadGrantLongDays)}
	}
	if !canonical.ValidHostID(in.HostID) {
		return &ReadGrantInputError{"the host is unknown"}
	}
	if validInspectContainer(in.Container) != nil {
		return &ReadGrantInputError{"the container name is not valid"}
	}
	if validImageLeaseImage(in.Image) != nil {
		return &ReadGrantInputError{"the image reference is not a digest-pinned image"}
	}
	return nil
}

// ProposeImageReadGrant proposes a read lease for one container and its
// pinned image on one host. The pair must be one ImageLeaseOptions of the host
// offers. The host passes the same exclusions as ProposeReadGrant. The
// executor's answer is checked like any read-grant proposal; the parameters
// of an accepted proposal are then stored for the lease page.
func (s *Service) ProposeImageReadGrant(ctx context.Context, user string, in ImageReadGrantRequest) (ReadGrantPreview, error) {
	if err := checkImageReadGrantRequest(in); err != nil {
		return ReadGrantPreview{}, err
	}
	exec, ok := s.exec.(readGrantProposer)
	if !ok {
		return ReadGrantPreview{}, ErrReadGrantProposeUnsupported
	}
	opts, err := s.ImageLeaseOptions(ctx, in.HostID)
	if err != nil {
		return ReadGrantPreview{}, err
	}
	if !slices.Contains(opts, ImageLeaseOption{Container: in.Container, Image: in.Image}) {
		return ReadGrantPreview{}, &ReadGrantInputError{"no recent inspection of this host names this container and image"}
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	pins, err := s.exec.ListHostKeys(cctx, &pb.ListHostKeysRequest{})
	if err != nil {
		return ReadGrantPreview{}, ErrReadGrantProposeFailed
	}
	var pin *pb.HostKeyPin
	for _, p := range pins.GetHosts() {
		if p.GetHostId() == in.HostID {
			pin = p
		}
	}
	if pin == nil || pin.GetBlocked() || !canonical.ValidHostKeyFingerprint(pin.GetFingerprint()) ||
		!credentialRefRe.MatchString(pin.GetCredentialRef()) {
		return ReadGrantPreview{}, ErrImageLeaseHost
	}
	ref := pin.GetCredentialRef()
	version, err := s.credentialVersion(ctx, ref)
	if err != nil {
		return ReadGrantPreview{}, err
	}
	now := s.now()
	doc := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, Issuer: readGrantIssuer,
		CreatedUnix: now.Unix(), ExpiryUnix: now.Add(time.Duration(in.Days) * 24 * time.Hour).Unix(),
		Trigger: permit.TriggerBoth, RateProfile: schedgrant.OrdinaryReadProfile,
		MinIntervalS: int64(ImageLeaseInterval / time.Second), RunBudget: ImageLeaseRunBudget,
		Targets:     []canonical.Target{{HostID: in.HostID, HostKeyFingerprint: pin.GetFingerprint()}},
		Credentials: []permit.ReadGrantCredential{{HostID: in.HostID, CredentialRef: ref, CredentialVersion: version}},
	}
	if doc.ID, err = newUUID(); err != nil {
		return ReadGrantPreview{}, err
	}
	params := imageLeaseParams(in)
	for _, p := range params {
		a, ok := actions.Lookup(p.ID)
		if !ok {
			return ReadGrantPreview{}, fmt.Errorf("image lease action %s: not an action", p.ID)
		}
		raw, err := json.Marshal(p.Params)
		if err != nil {
			return ReadGrantPreview{}, fmt.Errorf("encode image lease parameters: %w", err)
		}
		h, err := canonical.HashParameters(raw)
		if err != nil {
			return ReadGrantPreview{}, fmt.Errorf("hash image lease parameters: %w", err)
		}
		doc.Actions = append(doc.Actions, permit.ReadGrantAction{ActionID: a.ID, ModuleVersion: a.Version, ArtifactSHA256: a.SHA256(), ParametersHash: h})
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return ReadGrantPreview{}, fmt.Errorf("encode read grant: %w", err)
	}
	r, err := exec.ProposeReadGrant(cctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
	if err != nil {
		s.log.Warn("image read grant proposal refused", "code", status.Code(err).String())
		return ReadGrantPreview{}, ErrReadGrantProposeFailed
	}
	v, err := previewFromResponse(r, doc)
	if err != nil {
		s.log.Warn("image read grant proposal answer rejected", "error", err.Error())
		return ReadGrantPreview{}, err
	}
	v.ScopeKind = "hosts"
	v.Params = map[string]map[string]string{}
	for _, p := range params {
		v.Params[p.ID] = p.Params
	}
	if err := s.storeImageParams(ctx, v.ID, now, params); err != nil {
		s.log.Warn("image read grant parameters not stored", "grant", v.ID, "error", err.Error())
		return ReadGrantPreview{}, ErrReadGrantProposeFailed
	}
	s.log.Info("audit", "kind", "read_grant_proposed", "grant", v.ID, "digest", v.Digest, "user", user,
		"hosts", len(v.Targets), "actions", len(v.Actions))
	return v, nil
}

// storeImageParams writes the parameters of one image lease and removes the
// rows older than the longest read lease plus one day, in one transaction.
func (s *Service) storeImageParams(ctx context.Context, grant string, now time.Time, params []imageLeaseAction) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin image lease parameters: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // a committed transaction ignores the rollback
	for _, p := range params {
		raw, err := json.Marshal(p.Params)
		if err != nil {
			return fmt.Errorf("encode image lease parameters: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO read_grant_params (grant_id, action_id, params, created_at) VALUES (?, ?, ?, ?)`,
			grant, p.ID, string(raw), now.Unix()); err != nil {
			return fmt.Errorf("insert image lease parameters: %w", err)
		}
	}
	cutoff := now.Add(-(permit.ReadGrantMaxLifetime + 24*time.Hour)).Unix()
	if _, err := tx.ExecContext(ctx, `DELETE FROM read_grant_params WHERE created_at < ?`, cutoff); err != nil {
		return fmt.Errorf("prune image lease parameters: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit image lease parameters: %w", err)
	}
	return nil
}

// attachImageParams sets Params of each view from the stored parameters of
// its grant. A stored row is shown only when its parameters hash to the
// ParametersHash of the same action in the grant's document; views[i] and
// grants[i] are the same grant.
func (s *Service) attachImageParams(ctx context.Context, views []ReadGrantView, grants []*pb.ReadGrant) {
	if s.db == nil {
		return
	}
	for i, g := range grants {
		if i >= len(views) || views[i].ID == "" {
			continue
		}
		var doc permit.ReadGrantDoc
		if json.Unmarshal(g.GetCanonicalGrant(), &doc) != nil {
			continue
		}
		rows, err := s.db.QueryContext(ctx, `SELECT action_id, params FROM read_grant_params WHERE grant_id = ?`, views[i].ID)
		if err != nil {
			s.log.Warn("image read grant parameters not listed", "grant", views[i].ID, "error", err.Error())
			continue
		}
		for rows.Next() {
			var action, params string
			if err := rows.Scan(&action, &params); err != nil {
				break
			}
			if action != imageLeaseInspectAction && action != imageLeaseImageAction {
				continue
			}
			var p map[string]string
			if json.Unmarshal([]byte(params), &p) != nil || !matchesActionHash(doc, action, params) {
				continue
			}
			if views[i].Params == nil {
				views[i].Params = map[string]map[string]string{}
			}
			views[i].Params[action] = p
		}
		rows.Close()
	}
}

// matchesActionHash reports whether params hashes to the ParametersHash of
// action in doc.
func matchesActionHash(doc permit.ReadGrantDoc, action, params string) bool {
	h, err := canonical.HashParameters([]byte(params))
	if err != nil {
		return false
	}
	for _, a := range doc.Actions {
		if a.ActionID == action && a.ParametersHash == h {
			return true
		}
	}
	return false
}
