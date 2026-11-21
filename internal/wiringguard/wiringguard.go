// SPDX-License-Identifier: AGPL-3.0-or-later

package wiringguard

import (
	"bufio"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	// cmdDir is the directory whose package main programs are the roots of
	// the reachability walk.
	cmdDir = "cmd"
	// internalDir is the directory whose packages must be wired.
	internalDir = "internal"
	// maxAllowlistBytes limits how much of the allowlist file is read.
	maxAllowlistBytes = 64 << 10
	// allowlistFields is the number of "|"-separated fields in an entry:
	// package path, reason, ticket.
	allowlistFields = 3
	// docsDir is the planning-document directory whose Markdown files are
	// searched for ticket IDs, relative to the module root.
	docsDir = "docs"
	// ticketRegister lists wiring tickets that have no entry under docsDir,
	// relative to the module root. One ticket per line: "<ID> | <title>".
	ticketRegister = "internal/wiringguard/tickets.txt"
	// maxTicketSourceBytes limits how much of one planning document or the
	// ticket register is read.
	maxTicketSourceBytes = 1 << 20
)

// Reason categories. The reason of every allowlist entry starts with one of
// them, so triage can tell a package that a ticket will wire from a helper
// that must never be wired.
const (
	// CategoryPlanned: the named ticket wires the package.
	CategoryPlanned = "planned:"
	// CategoryTestHelper: the package is imported by tests only, by design.
	CategoryTestHelper = "test helper - never wired:"
	// CategoryDeveloperTool: a command run by hand or by make check, never by
	// a product command.
	CategoryDeveloperTool = "developer tool:"
)

// ErrNoModule is returned by FindModuleRoot when no go.mod exists in the
// start directory or any of its parents.
var ErrNoModule = errors.New("no go.mod found in any parent directory")

// generatedRe matches the comment marker that the Go tool treats as generated
// code.
var generatedRe = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.$`)

// ticketRe matches one ticket ID such as "AS-09", "iv02" or "M4-1".
var ticketRe = regexp.MustCompile(`^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$`)

// ticketWordRe finds ticket-like words in a planning document.
var ticketWordRe = regexp.MustCompile(`[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*`)

// Entry is one allowlist record: why an internal package is not wired yet and
// the ticket or plan item that will wire it.
type Entry struct {
	// Reason explains why the package is not reachable from cmd/.
	Reason string
	// Ticket names the ticket or plan item that wires the package.
	Ticket string
}

// Allowlist maps a module-relative package path such as "internal/web/enroll"
// to its Entry.
type Allowlist map[string]Entry

// Result is the outcome of Check. All paths are module-relative and slash
// separated, sorted.
type Result struct {
	// Checked is the number of candidate packages that were classified.
	Checked int
	// Unwired lists checked packages that are not reachable from cmd/ and have
	// no allowlist entry. These are the findings.
	Unwired []string
	// Allowed lists checked packages that are not reachable and have an entry.
	Allowed []string
	// NowWired lists packages that have an entry but are reachable now. The
	// entry can be removed; this is informational only.
	NowWired []string
	// Stale lists allowlist entries that name no checked package. These are
	// findings.
	Stale []string
}

// pkgInfo is what the scan records about one package directory.
type pkgInfo struct {
	// main is true when a non-test file declares package main.
	main bool
	// allGenerated is true when every non-test file carries the generated
	// marker.
	allGenerated bool
	// imports holds the module-internal directories this package imports.
	imports map[string]struct{}
}

// FindModuleRoot returns the nearest directory at or above start that
// contains a go.mod file.
func FindModuleRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", start, err)
	}
	for {
		info, err := os.Stat(filepath.Join(dir, "go.mod"))
		if err == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("find module root from %s: %w", start, ErrNoModule)
		}
		dir = parent
	}
}

// ParseAllowlist reads allowlist entries. Blank lines and lines starting with
// "#" are ignored. Every other line must have the form
//
//	<package path> | <reason> | <ticket>
//
// Every field must be non-empty, the reason must start with one of the
// Category constants, the ticket must be a single ID, and each package may
// appear once. Whether the ticket exists is checked by UnknownTickets.
func ParseAllowlist(r io.Reader) (Allowlist, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxAllowlistBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	if len(data) > maxAllowlistBytes {
		return nil, fmt.Errorf("read allowlist: larger than %d bytes", maxAllowlistBytes)
	}
	allow := Allowlist{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "|")
		if len(fields) != allowlistFields {
			return nil, fmt.Errorf("allowlist line %d: want %d fields separated by \"|\" (path | reason | ticket), got %d", line, allowlistFields, len(fields))
		}
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		pkg, reason, ticket := fields[0], fields[1], fields[2]
		if pkg == "" || path.Clean(pkg) != pkg || path.IsAbs(pkg) || strings.HasPrefix(pkg, "..") {
			return nil, fmt.Errorf("allowlist line %d: invalid package path %q", line, pkg)
		}
		if reason == "" {
			return nil, fmt.Errorf("allowlist line %d: %s has no reason", line, pkg)
		}
		if !hasCategory(reason) {
			return nil, fmt.Errorf("allowlist line %d: %s: reason must start with %q, %q or %q", line, pkg, CategoryPlanned, CategoryTestHelper, CategoryDeveloperTool)
		}
		if ticket == "" {
			return nil, fmt.Errorf("allowlist line %d: %s has no ticket or plan item", line, pkg)
		}
		if !ticketRe.MatchString(ticket) {
			return nil, fmt.Errorf("allowlist line %d: %s: ticket %q is not a single ID", line, pkg, ticket)
		}
		if _, dup := allow[pkg]; dup {
			return nil, fmt.Errorf("allowlist line %d: %s listed twice", line, pkg)
		}
		allow[pkg] = Entry{Reason: reason, Ticket: ticket}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	return allow, nil
}

// hasCategory reports whether reason starts with a known reason category.
func hasCategory(reason string) bool {
	for _, c := range []string{CategoryPlanned, CategoryTestHelper, CategoryDeveloperTool} {
		if strings.HasPrefix(reason, c) {
			return true
		}
	}
	return false
}

// UnknownTickets returns the sorted package paths of allow whose ticket ID
// does not appear as a whole ID in a Markdown file under root/docs or in the
// ticket register root/internal/wiringguard/tickets.txt. A missing register
// counts as empty; a missing docs directory is an error, so the check cannot
// pass by reading nothing.
func UnknownTickets(root string, allow Allowlist) ([]string, error) {
	known, err := ticketIDs(root)
	if err != nil {
		return nil, err
	}
	var unknown []string
	for pkg, entry := range allow {
		if !known[entry.Ticket] {
			unknown = append(unknown, pkg)
		}
	}
	sort.Strings(unknown)
	return unknown, nil
}

// ticketIDs collects the ticket IDs named in the planning documents and the
// first field of each line of the ticket register.
func ticketIDs(root string) (map[string]bool, error) {
	known := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, docsDir), func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", filepath.ToSlash(file), err)
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		data, err := readLimited(file, maxTicketSourceBytes)
		if err != nil {
			return err
		}
		for _, id := range ticketWordRe.FindAllString(string(data), -1) {
			known[id] = true
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read planning documents: %w", err)
	}
	data, err := readLimited(filepath.Join(root, ticketRegister), maxTicketSourceBytes)
	switch {
	case err == nil:
		for _, line := range strings.Split(string(data), "\n") {
			id, _, _ := strings.Cut(line, "|")
			if id = strings.TrimSpace(id); ticketRe.MatchString(id) {
				known[id] = true
			}
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	return known, nil
}

// readLimited reads file and fails when it is larger than limit bytes.
func readLimited(file string, limit int64) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.ToSlash(file), err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.ToSlash(file), err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("read %s: larger than %d bytes", filepath.ToSlash(file), limit)
	}
	return data, nil
}

// LoadAllowlist reads and parses the allowlist file at file.
func LoadAllowlist(file string) (Allowlist, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("load allowlist: %w", err)
	}
	defer f.Close()
	allow, err := ParseAllowlist(f)
	if err != nil {
		return nil, fmt.Errorf("load allowlist %s: %w", file, err)
	}
	return allow, nil
}

// Check scans the module rooted at root and classifies every candidate
// package against allow. Errors come from reading the tree or parsing a Go
// file; a parse error is not skipped, because a missed import would show up
// as a false finding.
func Check(root string, allow Allowlist) (Result, error) {
	modPath, err := modulePath(root)
	if err != nil {
		return Result{}, err
	}
	pkgs, err := scan(root, modPath)
	if err != nil {
		return Result{}, err
	}
	reached := reachable(pkgs)

	var res Result
	candidates := map[string]bool{}
	for dir, info := range pkgs {
		if !isCandidate(dir, info) {
			continue
		}
		candidates[dir] = true
		res.Checked++
		_, allowed := allow[dir]
		switch {
		case reached[dir] && allowed:
			res.NowWired = append(res.NowWired, dir)
		case reached[dir]:
		case allowed:
			res.Allowed = append(res.Allowed, dir)
		default:
			res.Unwired = append(res.Unwired, dir)
		}
	}
	for pkg := range allow {
		if !candidates[pkg] {
			res.Stale = append(res.Stale, pkg)
		}
	}
	sort.Strings(res.Unwired)
	sort.Strings(res.Allowed)
	sort.Strings(res.NowWired)
	sort.Strings(res.Stale)
	return res, nil
}

// isCandidate reports whether a package must be wired: it has production code
// (not only generated code) and lives under internal/, or it is a package main
// outside cmd/. Package main under cmd/ are the roots and need no wiring.
func isCandidate(dir string, info *pkgInfo) bool {
	if info.allGenerated {
		return false
	}
	if info.main {
		return !isUnder(dir, cmdDir)
	}
	return isUnder(dir, internalDir)
}

// isUnder reports whether dir is the parent directory or inside it.
func isUnder(dir, parent string) bool {
	return dir == parent || strings.HasPrefix(dir, parent+"/")
}

// reachable returns the set of package directories reachable from the package
// main programs under cmd/ through module-internal imports.
func reachable(pkgs map[string]*pkgInfo) map[string]bool {
	seen := map[string]bool{}
	var queue []string
	for dir, info := range pkgs {
		if info.main && isUnder(dir, cmdDir) {
			queue = append(queue, dir)
		}
	}
	for len(queue) > 0 {
		dir := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if seen[dir] {
			continue
		}
		seen[dir] = true
		info, ok := pkgs[dir]
		if !ok {
			continue
		}
		for target := range info.imports {
			if !seen[target] {
				queue = append(queue, target)
			}
		}
	}
	return seen
}

// modulePath returns the module path declared in root/go.mod.
func modulePath(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			mod, err := strconv.Unquote(fields[1])
			if err != nil {
				mod = fields[1]
			}
			return mod, nil
		}
	}
	return "", fmt.Errorf("read go.mod in %s: no module line", root)
}

// scan parses the imports of every non-test Go file under root and groups
// them by package directory. Directories named testdata, vendor, or starting
// with "." or "_" are skipped, as the Go tool skips them.
func scan(root, modPath string) (map[string]*pkgInfo, error) {
	pkgs := map[string]*pkgInfo{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", file, err)
		}
		if d.IsDir() {
			name := d.Name()
			if file != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			if file != root {
				// A directory with its own go.mod is a separate module; its
				// packages are not part of this module and are not scanned.
				_, err := os.Stat(filepath.Join(file, "go.mod"))
				switch {
				case err == nil:
					return filepath.SkipDir
				case !errors.Is(err, fs.ErrNotExist):
					return fmt.Errorf("check module boundary at %s: %w", filepath.ToSlash(file), err)
				}
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(file))
		if err != nil {
			return fmt.Errorf("relative path for %s: %w", file, err)
		}
		dir := filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly|parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse imports of %s: %w", filepath.ToSlash(file), err)
		}
		info := pkgs[dir]
		if info == nil {
			info = &pkgInfo{allGenerated: true, imports: map[string]struct{}{}}
			pkgs[dir] = info
		}
		if f.Name.Name == "main" {
			info.main = true
		}
		if !isGenerated(f) {
			info.allGenerated = false
		}
		for _, imp := range f.Imports {
			target, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return fmt.Errorf("import path in %s: %w", filepath.ToSlash(file), err)
			}
			if dir2, ok := moduleDir(target, modPath); ok {
				info.imports[dir2] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan module %s: %w", modPath, err)
	}
	return pkgs, nil
}

// isGenerated reports whether a file has the Go generated-code marker before
// its package clause. The file must be parsed with parser.ParseComments.
func isGenerated(f *ast.File) bool {
	for _, group := range f.Comments {
		if group.Pos() >= f.Package {
			break
		}
		for _, c := range group.List {
			if generatedRe.MatchString(c.Text) {
				return true
			}
		}
	}
	return false
}

// moduleDir maps an import path to a module-relative directory when the path
// belongs to modPath.
func moduleDir(importPath, modPath string) (string, bool) {
	switch {
	case importPath == modPath:
		return ".", true
	case strings.HasPrefix(importPath, modPath+"/"):
		return strings.TrimPrefix(importPath, modPath+"/"), true
	}
	return "", false
}
