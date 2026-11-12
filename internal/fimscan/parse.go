// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
)

// Options are the NOS-side parameters of one parse. All come from the read
// grant and executor storage, never from the host.
type Options struct {
	// Profile is the approved profile frozen by the grant.
	Profile Profile
	// Mode is the mode frozen by the grant.
	Mode Mode
	// HostKey is k_host (HostKeySize bytes), the per-host content key.
	HostKey []byte
}

// Parse reads one fim-scan-v1 document from r and validates it.
//
// It returns ErrInvalidResult (wrapped) when the document as a whole is
// unusable, the context error when ctx ends, and otherwise a Result whose
// Partial list says whether the run is complete.
func Parse(ctx context.Context, r io.Reader, opts Options) (*Result, error) {
	return parse(ctx, r, opts, defaultLimits)
}

// errCut is returned internally when the stream was cut at a byte limit.
var errCut = errors.New("cut")

type parser struct {
	ctx  context.Context
	dec  *json.Decoder
	cr   *countingReader
	lim  limits
	opts Options
	res  *Result

	cutReason Reason
	formatOK  bool

	recordEntries int
	mountEntries  int
	sshEntries    int
	sshBytes      int
	sshBad        bool
	sshSeen       bool
	rootsSeen     bool

	paths   map[string]int      // record path -> index in res.Records
	plains  [][sha256.Size]byte // plain hash per record, zeroed at the end
	hashed  []bool              // record carried a sha256
	rootRep map[string]string   // profile root -> reported status
}

func parse(ctx context.Context, r io.Reader, opts Options, lim limits) (*Result, error) {
	if err := opts.Profile.validate(); err != nil {
		return nil, err
	}
	if opts.Mode != ModeFull && opts.Mode != ModeIncremental {
		return nil, fmt.Errorf("%w: unknown mode", ErrBadOptions)
	}
	if len(opts.HostKey) != HostKeySize {
		return nil, fmt.Errorf("%w: host key must be %d bytes", ErrBadOptions, HostKeySize)
	}
	cr := &countingReader{ctx: ctx, r: r, docMax: lim.docBytes}
	dec := json.NewDecoder(cr)
	dec.UseNumber()
	p := &parser{
		ctx: ctx, dec: dec, cr: cr, lim: lim, opts: opts,
		res: &Result{
			Dropped: map[DropReason]int{},
		},
		paths:   map[string]int{},
		rootRep: map[string]string{},
	}
	err := p.document()
	if err != nil && !errors.Is(err, errCut) {
		return nil, err
	}
	if err := p.finish(err != nil); err != nil {
		return nil, err
	}
	return p.res, nil
}

func invalid(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidResult, detail)
}

// token reads the next token and maps reader errors: a byte limit cuts the
// stream, a context end aborts, everything else is a syntax error.
func (p *parser) token() (json.Token, error) {
	tok, err := p.dec.Token()
	if err == nil {
		return tok, nil
	}
	switch {
	case errors.Is(err, errDocLimit):
		p.cutReason = ReasonDocumentLimit
		return nil, errCut
	case errors.Is(err, errWindowLimit):
		p.cutReason = ReasonEntryLimit
		return nil, errCut
	case p.ctx.Err() != nil:
		return nil, fmt.Errorf("fimscan: read result: %w", p.ctx.Err())
	case errors.Is(err, io.EOF):
		return nil, invalid("unexpected end of document")
	default:
		// Syntax errors from encoding/json can quote a host byte; they are
		// replaced by a fixed text.
		return nil, invalid("malformed JSON")
	}
}

// more reports whether the current object or array has another element,
// with the next element's byte window already set.
func (p *parser) more(window int64) (bool, error) {
	p.cr.setWindow(p.dec.InputOffset(), window)
	if p.dec.More() {
		return true, nil
	}
	// More is false at the closing delimiter and on error; the closing
	// token read tells them apart.
	return false, nil
}

func (p *parser) expectDelim(d json.Delim) error {
	tok, err := p.token()
	if err != nil {
		return err
	}
	if got, ok := tok.(json.Delim); !ok || got != d {
		return invalid("unexpected token")
	}
	return nil
}

// key reads an object member name. ok is false when the name is not
// ASCII or repeats an earlier name under ASCII case folding.
func (p *parser) key(seen map[string]bool) (name string, ok bool, err error) {
	tok, err := p.token()
	if err != nil {
		return "", false, err
	}
	name, isStr := tok.(string)
	if !isStr {
		return "", false, invalid("unexpected token")
	}
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return "", false, nil
		}
	}
	folded := asciiLower(name)
	if seen[folded] {
		return "", false, nil
	}
	seen[folded] = true
	return name, true, nil
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// value reads one value. For an array or object it skips the whole value
// and returns isScalar false.
func (p *parser) value() (tok json.Token, isScalar bool, err error) {
	tok, err = p.token()
	if err != nil {
		return nil, false, err
	}
	if d, ok := tok.(json.Delim); ok {
		if d != '{' && d != '[' {
			return nil, false, invalid("unexpected token")
		}
		return nil, false, p.skipNested(1)
	}
	return tok, true, nil
}

// skipNested consumes tokens until depth open delimiters are closed.
func (p *parser) skipNested(depth int) error {
	for depth > 0 {
		if depth > maxNestingDepth {
			return invalid("nesting too deep")
		}
		tok, err := p.token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

// document parses the top-level object.
func (p *parser) document() error {
	p.cr.setWindow(0, p.lim.recordBytes)
	if err := p.expectDelim('{'); err != nil {
		return err
	}
	seen := map[string]bool{}
	for {
		more, err := p.more(p.lim.recordBytes)
		if err != nil {
			return err
		}
		if !more {
			break
		}
		name, ok, err := p.key(seen)
		if err != nil {
			return err
		}
		if !ok {
			return invalid("non-ASCII, duplicate or case-variant member name")
		}
		if err := p.member(name); err != nil {
			return err
		}
	}
	if err := p.expectDelim('}'); err != nil {
		return err
	}
	for _, m := range []string{"format", "profile", "mode", "started", "ended", "truncated", "counters", "roots", "records", "mounts"} {
		if !seen[m] {
			return invalid("missing member " + m)
		}
	}
	// Nothing may follow the document but whitespace.
	p.cr.setWindow(p.dec.InputOffset(), p.lim.recordBytes)
	if _, err := p.dec.Token(); !errors.Is(err, io.EOF) {
		if p.ctx.Err() != nil {
			return fmt.Errorf("fimscan: read result: %w", p.ctx.Err())
		}
		return invalid("data after the document")
	}
	return nil
}

func (p *parser) member(name string) error {
	switch name {
	case "format":
		s, err := p.stringMember()
		if err != nil {
			return err
		}
		if s != Format {
			return invalid("unknown format")
		}
		p.formatOK = true
	case "profile":
		s, err := p.stringMember()
		if err != nil {
			return err
		}
		if s != p.opts.Profile.ID {
			return invalid("profile does not match the grant")
		}
		p.res.ProfileID = s
	case "mode":
		s, err := p.stringMember()
		if err != nil {
			return err
		}
		if Mode(s) != p.opts.Mode {
			return invalid("mode does not match the grant")
		}
		p.res.Mode = Mode(s)
	case "started", "ended":
		v, err := p.intMember(MinTime, MaxTime)
		if err != nil {
			return err
		}
		if name == "started" {
			p.res.Started = v
		} else {
			p.res.Ended = v
		}
	case "truncated":
		tok, scalar, err := p.value()
		if err != nil {
			return err
		}
		b, ok := tok.(bool)
		if !scalar || !ok {
			return invalid("truncated is not a boolean")
		}
		if b {
			p.partial(ReasonHostTruncated)
		}
	case "counters":
		return p.counters()
	case "roots":
		if err := p.array(p.lim.recordBytes, p.rootEntry); err != nil {
			return err
		}
		p.rootsSeen = true
	case "records":
		return p.array(p.lim.recordBytes, p.recordEntry)
	case "mounts":
		return p.array(p.lim.recordBytes, p.mountEntry)
	case "ssh_config":
		if err := p.array(p.lim.sshEntry, p.sshEntry); err != nil {
			return err
		}
		p.sshSeen = true
	default:
		return invalid("unknown member")
	}
	return nil
}

func (p *parser) stringMember() (string, error) {
	tok, scalar, err := p.value()
	if err != nil {
		return "", err
	}
	s, ok := tok.(string)
	if !scalar || !ok {
		return "", invalid("member is not a string")
	}
	return s, nil
}

func (p *parser) intMember(lo, hi int64) (int64, error) {
	tok, scalar, err := p.value()
	if err != nil {
		return 0, err
	}
	v, ok := parseInt(tok, lo, hi)
	if !scalar || !ok {
		return 0, invalid("member is not an integer in range")
	}
	return v, nil
}

// parseInt accepts only a canonical JSON integer (no fraction, exponent,
// leading zero or "-0") within [lo, hi].
func parseInt(tok json.Token, lo, hi int64) (int64, bool) {
	n, ok := tok.(json.Number)
	if !ok || !canonicalInt(string(n)) {
		return 0, false
	}
	v, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || v < lo || v > hi {
		return 0, false
	}
	return v, true
}

func parseUint(tok json.Token) (uint64, bool) {
	n, ok := tok.(json.Number)
	if !ok || !canonicalInt(string(n)) || n[0] == '-' {
		return 0, false
	}
	v, err := strconv.ParseUint(string(n), 10, 64)
	return v, err == nil
}

func canonicalInt(s string) bool {
	if s == "" || len(s) > maxIntDigits {
		return false
	}
	d := s
	if d[0] == '-' {
		d = d[1:]
	}
	if d == "" || (d[0] == '0' && len(d) > 1) || s == "-0" {
		return false
	}
	for i := 0; i < len(d); i++ {
		if d[i] < '0' || d[i] > '9' {
			return false
		}
	}
	return true
}

func (p *parser) counters() error {
	if err := p.expectDelim('{'); err != nil {
		return err
	}
	seen := map[string]bool{}
	for {
		more, err := p.more(p.lim.recordBytes)
		if err != nil {
			return err
		}
		if !more {
			break
		}
		name, ok, err := p.key(seen)
		if err != nil {
			return err
		}
		if !ok {
			return invalid("bad counters member name")
		}
		v, err := p.intMember(0, 1<<40)
		if err != nil {
			return err
		}
		switch name {
		case "records":
			p.res.Host.Records = v
		case "mounts":
			p.res.Host.Mounts = v
		case "ssh_config":
			p.res.Host.SSHConfig = v
		case "unreadable":
			p.res.Host.Unreadable = v
		default:
			return invalid("unknown counters member")
		}
	}
	if err := p.expectDelim('}'); err != nil {
		return err
	}
	for _, m := range []string{"records", "mounts", "ssh_config", "unreadable"} {
		if !seen[m] {
			return invalid("missing counters member " + m)
		}
	}
	return nil
}

// array parses an array whose elements each get a byte window of size
// window and are handled by elem.
func (p *parser) array(window int64, elem func() error) error {
	if err := p.expectDelim('['); err != nil {
		return err
	}
	for {
		more, err := p.more(window)
		if err != nil {
			return err
		}
		if !more {
			break
		}
		if err := elem(); err != nil {
			return err
		}
	}
	return p.expectDelim(']')
}

func (p *parser) partial(r Reason) {
	if !slices.Contains(p.res.Partial, r) {
		p.res.Partial = append(p.res.Partial, r)
	}
}

func (p *parser) drop(d DropReason, r Reason) {
	p.res.Dropped[d]++
	p.partial(r)
}

// object reads one entry object, calling field for each member name that
// is ASCII and not repeated. It returns the drop reason for structural
// problems (not an object, bad or repeated member name, unknown member).
// field returns a drop reason for a bad value.
func (p *parser) object(field func(name string) (DropReason, error)) (DropReason, error) {
	tok, err := p.token()
	if err != nil {
		return "", err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		if ok && d == '[' {
			if err := p.skipNested(1); err != nil {
				return "", err
			}
		} else if ok {
			return "", invalid("unexpected token")
		}
		return DropNotObject, nil
	}
	var verdict DropReason
	seen := map[string]bool{}
	for p.dec.More() {
		name, ok, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !ok {
			if _, _, err := p.value(); err != nil {
				return "", err
			}
			if verdict == "" {
				verdict = DropBadMember
			}
			continue
		}
		d, err := field(name)
		if err != nil {
			return "", err
		}
		if verdict == "" {
			verdict = d
		}
	}
	if err := p.expectDelim('}'); err != nil {
		return "", err
	}
	return verdict, nil
}

// skipField consumes the value of an unknown member.
func (p *parser) skipField() (DropReason, error) {
	_, _, err := p.value()
	return DropBadMember, err
}

func (p *parser) stringField() (string, bool, error) {
	tok, scalar, err := p.value()
	if err != nil {
		return "", false, err
	}
	s, ok := tok.(string)
	return s, scalar && ok, nil
}

// pathField reads a base64 path and checks every record path rule.
func (p *parser) pathField() ([]byte, DropReason, error) {
	s, ok, err := p.stringField()
	if err != nil || !ok {
		return nil, DropBadPath, err
	}
	b, err := decodeBase64(s, MaxPathBytes)
	if err != nil {
		return nil, DropBadPath, nil
	}
	if validatePath(b) != nil {
		return nil, DropBadPath, nil
	}
	if !p.inProfile(b) {
		return nil, DropOutsideRoots, nil
	}
	return b, "", nil
}

func (p *parser) inProfile(b []byte) bool {
	for _, r := range p.opts.Profile.Roots {
		if matchRoot(r.Pattern, b) {
			return true
		}
	}
	return false
}

type rawRecord struct {
	rec    Record
	plain  [sha256.Size]byte
	hashed bool
	have   map[string]bool
}

func (p *parser) recordEntry() error {
	p.recordEntries++
	if p.recordEntries > p.lim.records {
		if _, _, err := p.value(); err != nil {
			return err
		}
		p.drop(DropOverLimit, ReasonRecordLimit)
		return nil
	}
	raw := rawRecord{have: map[string]bool{}}
	verdict, err := p.object(func(name string) (DropReason, error) {
		return p.recordField(&raw, name)
	})
	if err != nil {
		return err
	}
	if verdict == "" {
		verdict = raw.check()
	}
	if verdict == "" {
		if _, dup := p.paths[string(raw.rec.Path)]; dup {
			verdict = DropDuplicatePath
		}
	}
	if verdict != "" {
		p.drop(verdict, ReasonInvalidRecord)
		return nil
	}
	p.paths[string(raw.rec.Path)] = len(p.res.Records)
	p.res.Records = append(p.res.Records, raw.rec)
	p.plains = append(p.plains, raw.plain)
	p.hashed = append(p.hashed, raw.hashed)
	return nil
}

// check applies the cross-member rules of a record.
func (raw *rawRecord) check() DropReason {
	for _, m := range []string{"path", "type", "size", "mode", "uid", "gid", "inode", "mtime", "ctime"} {
		if !raw.have[m] {
			return DropMissingMember
		}
	}
	if raw.hashed && raw.rec.Type != TypeFile {
		return DropBadHash
	}
	if (raw.rec.Type == TypeSymlink) != raw.have["link"] {
		return DropBadLink
	}
	return ""
}

func (p *parser) recordField(raw *rawRecord, name string) (DropReason, error) {
	r := &raw.rec
	switch name {
	case "path":
		b, d, err := p.pathField()
		r.Path = b
		raw.have[name] = d == ""
		return d, err
	case "type":
		s, ok, err := p.stringField()
		if err != nil || !ok {
			return DropBadType, err
		}
		switch s {
		case "file":
			r.Type = TypeFile
		case "dir":
			r.Type = TypeDir
		case "symlink":
			r.Type = TypeSymlink
		case "other":
			r.Type = TypeOther
		default:
			return DropBadType, nil
		}
	case "size", "mode", "uid", "gid", "mtime", "ctime":
		tok, scalar, err := p.value()
		if err != nil {
			return "", err
		}
		lo, hi := int64(0), int64(1<<63-1)
		switch name {
		case "mode":
			hi = MaxMode
		case "uid", "gid":
			hi = MaxID
		case "mtime", "ctime":
			lo, hi = MinTime, MaxTime
		}
		v, ok := parseInt(tok, lo, hi)
		if !scalar || !ok {
			return DropBadInteger, nil
		}
		switch name {
		case "size":
			r.Size = v
		case "mode":
			r.Mode = uint32(v)
		case "uid":
			r.UID = uint32(v)
		case "gid":
			r.GID = uint32(v)
		case "mtime":
			r.Mtime = v
		case "ctime":
			r.Ctime = v
		}
	case "inode":
		tok, scalar, err := p.value()
		if err != nil {
			return "", err
		}
		v, ok := parseUint(tok)
		if !scalar || !ok {
			return DropBadInteger, nil
		}
		r.Inode = v
	case "sha256":
		s, ok, err := p.stringField()
		if err != nil || !ok || !lowerHex64(s) {
			return DropBadHash, err
		}
		if _, err := hex.Decode(raw.plain[:], []byte(s)); err != nil {
			return DropBadHash, nil
		}
		raw.hashed = true
	case "link":
		s, ok, err := p.stringField()
		if err != nil || !ok {
			return DropBadLink, err
		}
		b, err := decodeBase64(s, MaxLinkBytes)
		if err != nil || validateLink(b) != nil {
			return DropBadLink, nil
		}
		r.Link = b
	default:
		return p.skipField()
	}
	raw.have[name] = true
	return "", nil
}

func lowerHex64(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (p *parser) mountEntry() error {
	p.mountEntries++
	if p.mountEntries > p.lim.mounts {
		if _, _, err := p.value(); err != nil {
			return err
		}
		p.drop(DropOverLimit, ReasonMountLimit)
		return nil
	}
	var m Mount
	have := map[string]bool{}
	verdict, err := p.object(func(name string) (DropReason, error) {
		switch name {
		case "path":
			b, d, err := p.pathField()
			m.Path = b
			have[name] = d == ""
			return d, err
		case "fstype":
			s, ok, err := p.stringField()
			if err != nil || !ok || len(s) > MaxFSTypeBytes || !isIDString(s) {
				return DropBadFSType, err
			}
			m.FSType = s
			have[name] = true
			return "", nil
		default:
			return p.skipField()
		}
	})
	if err != nil {
		return err
	}
	if verdict == "" && (!have["path"] || !have["fstype"]) {
		verdict = DropMissingMember
	}
	if verdict != "" {
		p.drop(verdict, ReasonInvalidMount)
		return nil
	}
	p.res.Mounts = append(p.res.Mounts, m)
	return nil
}

func (p *parser) rootEntry() error {
	var root, status string
	verdict, err := p.object(func(name string) (DropReason, error) {
		switch name {
		case "root", "status":
			s, ok, err := p.stringField()
			if err != nil || !ok {
				return DropBadRoot, err
			}
			if name == "root" {
				root = s
			} else {
				status = s
			}
			return "", nil
		default:
			return p.skipField()
		}
	})
	if err != nil {
		return err
	}
	if verdict == "" {
		known := slices.ContainsFunc(p.opts.Profile.Roots, func(r Root) bool { return r.Pattern == root })
		_, dup := p.rootRep[root]
		okStatus := status == "scanned" || status == "missing" || status == "error"
		if !known || dup || !okStatus {
			verdict = DropBadRoot
		}
	}
	if verdict != "" {
		p.drop(verdict, ReasonInvalidRoot)
		return nil
	}
	p.rootRep[root] = status
	return nil
}

func (p *parser) sshEntry() error {
	p.sshEntries++
	var f SSHConfigFile
	have := map[string]bool{}
	verdict, err := p.object(func(name string) (DropReason, error) {
		switch name {
		case "path":
			b, d, err := p.pathField()
			f.Path = b
			have[name] = d == ""
			return d, err
		case "content":
			s, ok, err := p.stringField()
			if err != nil || !ok {
				return DropBadMember, err
			}
			var b []byte
			if s != "" {
				b, err = decodeBase64(s, p.lim.sshBytes)
				if err != nil {
					return DropBadMember, nil
				}
			}
			f.Content = b
			have[name] = true
			return "", nil
		default:
			return p.skipField()
		}
	})
	if err != nil {
		return err
	}
	p.sshBytes += len(f.Content)
	if verdict != "" || !have["path"] || !have["content"] ||
		p.sshEntries > p.lim.sshFiles || p.sshBytes > p.lim.sshBytes ||
		slices.ContainsFunc(p.res.SSHConfig, func(o SSHConfigFile) bool { return string(o.Path) == string(f.Path) }) {
		p.sshBad = true
		return nil
	}
	if !p.sshBad {
		p.res.SSHConfig = append(p.res.SSHConfig, f)
	}
	return nil
}

// finish applies the run-level checks and seals the content hashes.
func (p *parser) finish(cut bool) error {
	res := p.res
	if cut {
		// A cut document is usable only when it is known to be the
		// granted format, profile and mode.
		if res.ProfileID == "" || res.Mode == "" || !p.formatOK {
			return invalid("document cut before its header was validated")
		}
		p.partial(p.cutReason)
	}

	// Roots: the executor classifies with the profile's optional flags.
	scanned := map[string]bool{}
	for _, r := range p.opts.Profile.Roots {
		st := RootStatus{Pattern: r.Pattern, State: RootSkipped}
		switch p.rootRep[r.Pattern] {
		case "scanned":
			st.State = RootScanned
			scanned[r.Pattern] = true
		case "missing":
			if r.Optional {
				st.State = RootAbsent
			}
		}
		if st.State == RootSkipped {
			p.partial(ReasonRootSkipped)
		}
		res.Roots = append(res.Roots, st)
	}
	if p.rootsSeen {
		// A record below no scanned root contradicts the roots summary.
		keep := res.Records[:0]
		keepPlain := p.plains[:0]
		keepHashed := p.hashed[:0]
		for i, rec := range res.Records {
			if !slices.ContainsFunc(p.opts.Profile.Roots, func(r Root) bool {
				return scanned[r.Pattern] && matchRoot(r.Pattern, rec.Path)
			}) {
				p.drop(DropRootNotScanned, ReasonInvalidRecord)
				continue
			}
			keep = append(keep, rec)
			keepPlain = append(keepPlain, p.plains[i])
			keepHashed = append(keepHashed, p.hashed[i])
		}
		clear(p.plains[len(keepPlain):])
		res.Records, p.plains, p.hashed = keep, keepPlain, keepHashed
		clear(p.paths)
		for i, rec := range res.Records {
			p.paths[string(rec.Path)] = i
		}
	}

	if !cut {
		if res.Host.Records != int64(p.recordEntries) || res.Host.Mounts != int64(p.mountEntries) ||
			res.Host.SSHConfig != int64(p.sshEntries) {
			p.partial(ReasonCounterMismatch)
		}
		if res.Host.Unreadable > 0 {
			p.partial(ReasonUnreadable)
		}
	}

	p.sshConfigState(cut)

	for i := range res.Records {
		if p.hashed[i] {
			res.Records[i].Hash = sealHash(p.opts.HostKey, res.Records[i].Path, p.plains[i])
		}
	}
	clear(p.plains)
	return nil
}

func (p *parser) sshConfigState(cut bool) {
	res := p.res
	switch {
	case !p.sshSeen || cut:
		res.SSHConfigState = SSHConfigMissing
	case p.sshBad:
		res.SSHConfigState = SSHConfigInvalid
	default:
		res.SSHConfigState = SSHConfigValid
		for _, f := range res.SSHConfig {
			i, ok := p.paths[string(f.Path)]
			if !ok || res.Records[i].Type != TypeFile || !p.hashed[i] || sha256.Sum256(f.Content) != p.plains[i] {
				res.SSHConfigState = SSHConfigInconsistent
				break
			}
		}
	}
	if res.SSHConfigState != SSHConfigValid {
		clear(res.SSHConfig)
		res.SSHConfig = nil
		p.partial(ReasonSSHConfig)
	}
}
