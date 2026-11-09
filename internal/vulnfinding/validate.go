// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfinding

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Patterns for record fields. All are anchored, ASCII and length-bounded.
var (
	// vulnIDRe is the D2 pattern for primary IDs and aliases.
	vulnIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{1,63}$`)
	// cveRe recognises CVE IDs in any letter case for canonicalisation.
	cveRe = regexp.MustCompile(`^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,19}$`)
	// subjectIDRe matches inventory host IDs (internal/inventory) and is
	// used for device IDs too.
	subjectIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	// imageDigestRe is a platform image digest.
	imageDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// Ecosystems (D2).
	debianEcoRe = regexp.MustCompile(`^debian:[a-z]{2,32}$`)
	ubuntuEcoRe = regexp.MustCompile(`^ubuntu:[0-9]{2}\.[0-9]{2}$`)
	alpineEcoRe = regexp.MustCompile(`^alpine:[0-9]{1,2}\.[0-9]{1,3}$`)
	ciscoEcoRe  = regexp.MustCompile(`^vendor:cisco:[a-z0-9-]{1,32}$`)
	// distroPkgRe is a Debian, Ubuntu or Alpine package name.
	distroPkgRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{1,127}$`)
	// osvPkgRe is a package name in an OSV language ecosystem (Go module
	// paths, npm scopes, Maven group:artifact).
	osvPkgRe = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@/._+:~-]{0,213}$`)
	// modelRe is a device model.
	modelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	// versionRe is a package, firmware or fixed version (dpkg, apk, semver,
	// vendor trains).
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$`)
	// sourceIDRe is the D5 feed source ID pattern.
	sourceIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)
	// snapshotIDRe is a Hermes snapshot ID (an assertion stored for audit).
	snapshotIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$`)
	// matcherVersionRe is the Hermes matcher version.
	matcherVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
	// cvssVectorRe bounds the vector's characters and length.
	cvssVectorRe = regexp.MustCompile(`^[A-Za-z0-9:./]{1,255}$`)
)

// osvEcosystems are the OSV language ecosystems NOS accepts.
var osvEcosystems = map[string]bool{
	"Go": true, "npm": true, "PyPI": true, "crates.io": true, "Maven": true,
	"NuGet": true, "Packagist": true, "RubyGems": true, "Pub": true, "Hex": true,
}

// ecoClass groups ecosystems for the consistency rules.
type ecoClass int

const (
	ecoDistro ecoClass = iota + 1 // debian, ubuntu, alpine
	ecoOSV                        // OSV language ecosystems
	ecoVendor                     // vendor:* (devices)
)

const dateLayout = "2006-01-02"

// Validate checks a decoded record against the D2 model and returns the
// finding with its NOS-computed key. CVE IDs are canonicalised to upper
// case before the key is computed.
func Validate(r Record) (Finding, error) {
	r.Vuln = canonicalVuln(r.Vuln)
	class, err := validateSubjectAndEcosystem(&r)
	if err != nil {
		return Finding{}, err
	}
	if err := validateComponent(&r, class); err != nil {
		return Finding{}, err
	}
	if err := validateVuln(r.Vuln); err != nil {
		return Finding{}, err
	}
	if err := validateFix(r.Fix); err != nil {
		return Finding{}, err
	}
	if err := validateMatchBasis(r.MatchBasis, class); err != nil {
		return Finding{}, err
	}
	note, err := validateTracker(&r)
	if err != nil {
		return Finding{}, err
	}
	if err := validateScores(r.Scores); err != nil {
		return Finding{}, err
	}
	if err := validateEvidence(r.Evidence); err != nil {
		return Finding{}, err
	}
	if err := validateAssessmentText(r.Assessment.Text); err != nil {
		return Finding{}, err
	}
	return Finding{Record: r, Key: keyOf(&r), TrackerNote: note}, nil
}

func missing(field string) error { return fmt.Errorf("%s: %w", field, ErrMissingField) }
func invalid(field string) error { return fmt.Errorf("%s: %w", field, ErrInvalidField) }

// checkPattern checks a required field against its pattern.
func checkPattern(field, v string, re *regexp.Regexp) error {
	if v == "" {
		return missing(field)
	}
	if !re.MatchString(v) {
		return invalid(field)
	}
	return nil
}

func canonicalVuln(v Vuln) Vuln {
	out := Vuln{ID: canonicalID(v.ID)}
	if v.Aliases != nil {
		out.Aliases = make([]string, len(v.Aliases))
		for i, a := range v.Aliases {
			out.Aliases[i] = canonicalID(a)
		}
	}
	return out
}

func canonicalID(id string) string {
	if cveRe.MatchString(id) {
		return strings.ToUpper(id)
	}
	return id
}

func classifyEcosystem(eco string) (ecoClass, error) {
	switch {
	case eco == "":
		return 0, missing("ecosystem")
	case eco == "proxmox":
		return 0, fmt.Errorf("ecosystem: %w", ErrCoverageOnly)
	case debianEcoRe.MatchString(eco), ubuntuEcoRe.MatchString(eco), alpineEcoRe.MatchString(eco):
		return ecoDistro, nil
	case osvEcosystems[eco]:
		return ecoOSV, nil
	case ciscoEcoRe.MatchString(eco), eco == "vendor:paloalto:panos":
		return ecoVendor, nil
	default:
		return 0, invalid("ecosystem")
	}
}

func validateSubjectAndEcosystem(r *Record) (ecoClass, error) {
	switch r.SubjectKind {
	case SubjectHost, SubjectImage, SubjectDevice:
	case "":
		return 0, missing("subject_kind")
	default:
		return 0, invalid("subject_kind")
	}
	if err := checkPattern("subject_ref.id", r.SubjectRef.ID, subjectIDRe); err != nil {
		return 0, err
	}
	if r.SubjectKind == SubjectImage {
		if err := checkPattern("subject_ref.image_digest", r.SubjectRef.ImageDigest, imageDigestRe); err != nil {
			return 0, err
		}
	} else if r.SubjectRef.ImageDigest != "" {
		return 0, fmt.Errorf("subject_ref.image_digest on a %s subject: %w", r.SubjectKind, ErrInconsistent)
	}
	class, err := classifyEcosystem(r.Ecosystem)
	if err != nil {
		return 0, err
	}
	if (r.SubjectKind == SubjectDevice) != (class == ecoVendor) {
		return 0, fmt.Errorf("ecosystem does not fit subject kind %s: %w", r.SubjectKind, ErrInconsistent)
	}
	return class, nil
}

func validateComponent(r *Record, class ecoClass) error {
	c := r.Component
	if r.SubjectKind == SubjectDevice {
		if c.SourcePackage != "" || c.SourceVersion != "" || len(c.Binaries) != 0 {
			return fmt.Errorf("component: package fields on a device: %w", ErrInconsistent)
		}
		if err := checkPattern("component.model", c.Model, modelRe); err != nil {
			return err
		}
		return checkPattern("component.firmware", c.Firmware, versionRe)
	}
	if c.Model != "" || c.Firmware != "" {
		return fmt.Errorf("component: device fields on a %s: %w", r.SubjectKind, ErrInconsistent)
	}
	pkgRe := distroPkgRe
	if class == ecoOSV {
		pkgRe = osvPkgRe
	}
	if err := checkPattern("component.source_package", c.SourcePackage, pkgRe); err != nil {
		return err
	}
	if err := checkPattern("component.source_version", c.SourceVersion, versionRe); err != nil {
		return err
	}
	if class == ecoDistro && !strings.HasPrefix(r.Ecosystem, "alpine:") &&
		(strings.HasPrefix(c.SourcePackage, "linux-signed") || strings.HasPrefix(c.SourcePackage, "linux-meta")) {
		return fmt.Errorf("component.source_package: %w", ErrKernelSourcePackage)
	}
	if len(c.Binaries) > MaxBinaries {
		return invalid("component.binaries")
	}
	seen := make(map[string]struct{}, len(c.Binaries))
	for i, b := range c.Binaries {
		field := fmt.Sprintf("component.binaries[%d]", i)
		if err := checkPattern(field+".name", b.Name, pkgRe); err != nil {
			return err
		}
		if err := checkPattern(field+".version", b.Version, versionRe); err != nil {
			return err
		}
		if _, dup := seen[b.Name]; dup {
			return invalid(field + ".name")
		}
		seen[b.Name] = struct{}{}
	}
	return nil
}

func validateVuln(v Vuln) error {
	if err := checkPattern("vuln.id", v.ID, vulnIDRe); err != nil {
		return err
	}
	if len(v.Aliases) > MaxAliases {
		return invalid("vuln.aliases")
	}
	seen := map[string]struct{}{v.ID: {}}
	for i, a := range v.Aliases {
		field := fmt.Sprintf("vuln.aliases[%d]", i)
		if !vulnIDRe.MatchString(a) {
			return invalid(field)
		}
		if _, dup := seen[a]; dup {
			return invalid(field)
		}
		seen[a] = struct{}{}
	}
	return nil
}

func validateFix(f Fix) error {
	switch f.State {
	case FixFixed:
		return checkPattern("fix.version", f.Version, versionRe)
	case FixNoFixYet, FixWontFix, FixNotAffected:
		if f.Version != "" {
			return fmt.Errorf("fix.version with state %s: %w", f.State, ErrInconsistent)
		}
		return nil
	case "":
		return missing("fix.state")
	default:
		return invalid("fix.state")
	}
}

// validateMatchBasis: distro trackers only for distro ecosystems, vendor
// advisories only for devices, OSV ranges never for devices, and CPE
// ranges never for distro packages (D4).
func validateMatchBasis(b MatchBasis, class ecoClass) error {
	var ok bool
	switch b {
	case MatchDistroTracker:
		ok = class == ecoDistro
	case MatchOSVRange:
		ok = class != ecoVendor
	case MatchVendorAdvisory:
		ok = class == ecoVendor
	case MatchCPE:
		ok = class != ecoDistro
	case "":
		return missing("match_basis")
	default:
		return invalid("match_basis")
	}
	if !ok {
		return fmt.Errorf("match_basis %s does not fit the ecosystem: %w", b, ErrInconsistent)
	}
	return nil
}

// validateTracker requires a tracker state exactly for Debian
// distro_tracker records and checks the record's fix is the state's one
// target (D4). It returns NOS's tracker note.
func validateTracker(r *Record) (string, error) {
	debianTracker := r.MatchBasis == MatchDistroTracker && strings.HasPrefix(r.Ecosystem, "debian:")
	if !debianTracker {
		if r.TrackerState != "" {
			return "", fmt.Errorf("tracker_state outside a Debian distro_tracker record: %w", ErrInconsistent)
		}
		return "", nil
	}
	if r.TrackerState == "" {
		return "", missing("tracker_state")
	}
	m, err := MapDebianTrackerState(r.TrackerState)
	if err != nil {
		return "", err
	}
	if r.Fix.State != m.Fix {
		return "", fmt.Errorf("fix.state %s does not match tracker_state: %w", r.Fix.State, ErrInconsistent)
	}
	return m.Note, nil
}

func validateScores(s Scores) error {
	if c := s.CVSS; c != nil {
		var prefix string
		switch c.Version {
		case "2.0":
		case "3.0", "3.1", "4.0":
			prefix = "CVSS:" + c.Version + "/"
		default:
			return invalid("scores.cvss.version")
		}
		if !cvssVectorRe.MatchString(c.Vector) {
			return invalid("scores.cvss.vector")
		}
		if prefix != "" && !strings.HasPrefix(c.Vector, prefix) || prefix == "" && strings.HasPrefix(c.Vector, "CVSS:") {
			return invalid("scores.cvss.vector")
		}
		if !inRange(c.BaseScore, 0, 10) || !oneDecimal(c.BaseScore) {
			return invalid("scores.cvss.base_score")
		}
		switch c.Source {
		case CVSSSourceDistro, CVSSSourceNVD, CVSSSourceVendor:
		default:
			return invalid("scores.cvss.source")
		}
	}
	if k := s.KEV; k != nil {
		if !validDate(k.DateAdded) {
			return invalid("scores.kev.date_added")
		}
	}
	if e := s.EPSS; e != nil {
		if !inRange(e.Probability, 0, 1) {
			return invalid("scores.epss.probability")
		}
		if !inRange(e.Percentile, 0, 1) {
			return invalid("scores.epss.percentile")
		}
		if !validDate(e.Date) {
			return invalid("scores.epss.date")
		}
	}
	return nil
}

func inRange(v, lo, hi float64) bool {
	return !math.IsNaN(v) && v >= lo && v <= hi
}

func oneDecimal(v float64) bool {
	return math.Abs(v*10-math.Round(v*10)) < 1e-9
}

func validDate(s string) bool {
	if len(s) != len(dateLayout) {
		return false
	}
	_, err := time.Parse(dateLayout, s)
	return err == nil
}

func validateEvidence(e Evidence) error {
	if len(e.BasisSources) == 0 {
		return ErrEmptyBasisSources
	}
	if len(e.BasisSources) > MaxBasisSources {
		return invalid("evidence.basis_sources")
	}
	seen := make(map[string]struct{}, len(e.BasisSources))
	for i, b := range e.BasisSources {
		field := fmt.Sprintf("evidence.basis_sources[%d]", i)
		if !sourceIDRe.MatchString(b.SourceID) {
			return invalid(field + ".source_id")
		}
		if _, dup := seen[b.SourceID]; dup {
			return invalid(field + ".source_id")
		}
		seen[b.SourceID] = struct{}{}
		if !snapshotIDRe.MatchString(b.SnapshotID) {
			return invalid(field + ".snapshot_id")
		}
		switch b.Integrity {
		case IntegritySigned, IntegrityChecksum, IntegrityNone:
		default:
			return invalid(field + ".integrity")
		}
	}
	return checkPattern("evidence.matcher_version", e.MatcherVersion, matcherVersionRe)
}

// validateAssessmentText enforces at most MaxAssessmentBytes of printable
// UTF-8: line feed and tab are the only control characters, and bidi
// embedding, override and isolate controls, which could reorder the text
// around it on screen, are rejected, as is U+FFFD.
func validateAssessmentText(s string) error {
	const field = "assessment.text"
	if len(s) > MaxAssessmentBytes {
		return invalid(field)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s: %w", field, ErrInvalidUTF8)
	}
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
		case unicode.IsControl(r), r == utf8.RuneError, isBidiControl(r):
			return invalid(field)
		}
	}
	return nil
}

func isBidiControl(r rune) bool {
	// U+061C ALM, U+200E LRM, U+200F RLM, U+202A-U+202E embeddings and
	// overrides, U+2066-U+2069 isolates.
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}
