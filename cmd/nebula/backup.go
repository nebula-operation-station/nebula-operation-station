// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/backup"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
)

// Backup and restore (spec 15, M10-2). `sudo nebula backup` reads the
// server's part itself as root, then drops to the admin who ran sudo and
// asks the executor for its part (admin role); the archive is written as
// that admin, encrypted with age to /etc/nebula/backup-recipients.
// `sudo nebula restore` is CRITICAL and needs the word "restore" typed.

// Where Nebula lives (a variable so tests can point it elsewhere).
var nebulaRoot = "/"

func rootPath(p ...string) string { return filepath.Join(append([]string{nebulaRoot}, p...)...) }

const recipientsFile = "etc/nebula/backup-recipients"

var dropInRe = regexp.MustCompile(`^[0-9a-z][0-9a-z-]{0,40}\.conf$`)

// adminFromSudo returns the user who ran sudo.
func adminFromSudo() (*user.User, error) {
	uid := os.Getenv("SUDO_UID")
	if os.Geteuid() != 0 || uid == "" || uid == "0" {
		return nil, errors.New("run this with sudo as an admin user (it reads the server's data as root and asks the executor as you)")
	}
	return user.LookupId(uid)
}

// dropTo makes the whole process the given user, with its groups (the
// executor socket needs nebula-rpc).
func dropTo(u *user.User) error {
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return errors.New("cannot parse the admin user's IDs")
	}
	gids, err := u.GroupIds()
	if err != nil {
		return err
	}
	var groups []int
	for _, g := range gids {
		if n, err := strconv.Atoi(g); err == nil {
			groups = append(groups, n)
		}
	}
	if err := syscall.Setgroups(groups); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setresgid(gid, gid, gid); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	if os.Geteuid() == 0 {
		return errors.New("could not drop root")
	}
	return nil
}

// ExitSkipped is the exit status of `nebula backup --pre-upgrade` when it
// made no backup. It is not 0: an upgrade must never take a skipped backup
// for a made one (review m105, the HIGH finding).
const ExitSkipped = 3

// exitError carries a specific exit status to main.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func skipped(reason string) error {
	return &exitError{code: ExitSkipped, msg: "backup: no backup was made: " + reason}
}

// hostname is os.Hostname (a variable for tests).
var hostname = os.Hostname

// readRegular reads a small configuration file only if it is a regular
// file, not a symbolic link or anything else (review m102, F6).
func readRegular(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return nil, fmt.Errorf("%s is not a regular file of at most 1 MiB", p)
	}
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

// readServerPart reads the server's database (a checked snapshot) and the
// configuration, as root.
func readServerPart(tmp string) ([]backup.File, int, error) {
	snap := filepath.Join(tmp, "server.db")
	v, err := backup.SnapshotSQLite(rootPath("var", "lib", "nebula", "server", "server.db"), snap)
	if err != nil {
		return nil, 0, err
	}
	// Bounded before it is read into memory (review m102, F1).
	if fi, err := os.Stat(snap); err != nil {
		return nil, 0, err
	} else if fi.Size() > backup.MaxFileSize {
		return nil, 0, fmt.Errorf("server.db is %d MiB, more than a backup holds (%d MiB)", fi.Size()>>20, backup.MaxFileSize>>20)
	}
	b, err := os.ReadFile(snap)
	if err != nil {
		return nil, 0, err
	}
	files := []backup.File{{Path: backup.ServerDB, Mode: 0o600, Data: b}}
	for name, p := range map[string]string{"server.json": "etc/nebula/server.json", "backup-recipients": recipientsFile} {
		if b, err := readRegular(rootPath(p)); err == nil {
			files = append(files, backup.File{Path: "server/config/" + name, Mode: 0o640, Data: b})
		}
	}
	for _, unit := range []string{"nebula-executor", "nebula-server"} {
		dir := rootPath("etc", "systemd", "system", unit+".service.d")
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if !dropInRe.MatchString(e.Name()) || !e.Type().IsRegular() {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
				files = append(files, backup.File{Path: "server/systemd/" + unit + ".service.d/" + e.Name(), Mode: 0o644, Data: b})
			}
		}
	}
	return files, v, nil
}

func backupCmd(args []string, stdin io.Reader, w io.Writer) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "archive to write (default ~/nebula-backups/nebula-backup-<time>.tar.gz.age)")
	full := fs.Bool("full", false, "full backup (execution logs and artifacts live in server.db, so every backup has them)")
	noEncrypt := fs.Bool("no-encrypt", false, "write the archive unencrypted (asks to type \"unencrypted\")")
	preUpgrade := fs.Bool("pre-upgrade", false, "the backup before an upgrade: no questions; exits 3 when it makes none")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: sudo nebula backup [--out FILE] [--full] [--no-encrypt] [--pre-upgrade]")
	}
	admin, err := adminFromSudo()
	if err != nil {
		if *preUpgrade {
			return skipped("needs sudo from an admin user: " + err.Error())
		}
		return err
	}
	var recipients []age.Recipient
	if !*noEncrypt {
		b, err := readRegular(rootPath(recipientsFile))
		if err == nil {
			recipients, err = backup.ParseRecipients(b)
		}
		if err != nil || len(recipients) == 0 {
			msg := fmt.Sprintf("no backup recipients in /%s: create a key with `age-keygen -o nebula-backup.key` on a machine you keep safe, "+
				"and put its public key (age1…) into that file", recipientsFile)
			if *preUpgrade {
				return skipped(msg)
			}
			return errors.New(msg)
		}
	} else {
		if *preUpgrade {
			return errors.New("--pre-upgrade cannot write an unencrypted backup")
		}
		fmt.Fprint(w, "The archive will hold the inventory and audit data unencrypted. Type \"unencrypted\" to continue: ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(line) != "unencrypted" {
			return errors.New("not confirmed; nothing written")
		}
	}
	tmp, err := os.MkdirTemp("", "nebula-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	files, serverSchema, err := readServerPart(tmp)
	if err != nil {
		return err
	}
	_ = os.RemoveAll(tmp) // the snapshot is in memory now
	if err := dropTo(admin); err != nil {
		return err
	}
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	resp, err := pb.NewExecutorServiceClient(conn).BackupExecutor(ctx, &pb.BackupExecutorRequest{})
	if err != nil {
		if *preUpgrade && grpcstatus.Code(err) == codes.Unimplemented {
			return skipped("the running executor is older than backups")
		}
		return fmt.Errorf("the executor's part: %w", err)
	}
	for _, f := range resp.GetFiles() {
		files = append(files, backup.File{Path: "executor/" + f.GetName(), Mode: f.GetMode(), Data: f.GetData()})
	}
	host, _ := os.Hostname()
	now := time.Now().UTC()
	kind := "config"
	if *full {
		kind = "full"
	}
	m := backup.Manifest{Version: version.String(), CreatedAt: now.Format(time.RFC3339), Host: host, Kind: kind,
		Schemas: map[string]int{"server": serverSchema, "executor": int(resp.GetSchemaVersion())}}
	path := *out
	if path == "" {
		dir := filepath.Join(admin.HomeDir, "nebula-backups")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		name := "nebula-backup-" + now.Format("20060102-150405") + ".tar.gz"
		if len(recipients) > 0 {
			name += ".age"
		}
		path = filepath.Join(dir, name)
	}
	sum, size, err := writeArchiveFile(path, m, files, recipients)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "wrote %s (%d bytes, %d files, sha256 %s)\n", path, size, len(files), sum)
	if len(recipients) > 0 {
		fmt.Fprintf(w, "encrypted to %d recipient(s) from /%s; keep the age identity somewhere else than this machine\n", len(recipients), recipientsFile)
	}
	fmt.Fprintln(w, "copy it off this machine (for example with restic); restore with: sudo nebula restore --identity KEY FILE")
	return nil
}

// writeArchiveFile writes the archive next to path, reads it back to
// check what is on disk, and renames it into place.
func writeArchiveFile(path string, m backup.Manifest, files []backup.File, recipients []age.Recipient) (string, int64, error) {
	tmp := path + ".partial"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp)
	h := sha256.New()
	if err := backup.Write(io.MultiWriter(f, h), m, files, recipients); err != nil {
		f.Close()
		return "", 0, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", 0, err
	}
	if err := f.Close(); err != nil {
		return "", 0, err
	}
	written := hex.EncodeToString(h.Sum(nil))
	// Read back streaming, never the whole archive in memory (review
	// m102, F1).
	rf, err := os.Open(tmp)
	if err != nil {
		return "", 0, err
	}
	again := sha256.New()
	size, err := io.Copy(again, rf)
	rf.Close()
	if err != nil {
		return "", 0, err
	}
	if hex.EncodeToString(again.Sum(nil)) != written {
		return "", 0, errors.New("the archive on disk differs from what was written")
	}
	if len(recipients) == 0 {
		rf, err := os.Open(tmp)
		if err != nil {
			return "", 0, err
		}
		_, _, err = backup.Read(rf, nil)
		rf.Close()
		if err != nil {
			return "", 0, fmt.Errorf("the written archive does not read back: %w", err)
		}
	}
	if _, err := os.Lstat(path); err == nil {
		return "", 0, fmt.Errorf("%s exists", path)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", 0, err
	}
	return written, size, nil
}

// systemctl is the System of a real machine.
type systemctl struct{}

func (systemctl) Stop(units ...string) error {
	return exec.Command("systemctl", append([]string{"stop"}, units...)...).Run()
}

func (systemctl) Start(units ...string) error {
	return exec.Command("systemctl", append([]string{"start"}, units...)...).Run()
}

func (systemctl) Chown(path, name string) error {
	if name == "root" {
		return os.Lchown(path, 0, 0)
	}
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return os.Lchown(path, uid, gid)
}

func restoreCmd(args []string, stdin io.Reader, w io.Writer) error {
	return restoreWith(args, stdin, w, systemctl{}, time.Now())
}

func restoreWith(args []string, stdin io.Reader, w io.Writer, sys backup.System, now time.Time) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	identity := fs.String("identity", "", "age identity file (for an encrypted archive)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: sudo nebula restore [--identity FILE] ARCHIVE")
	}
	if os.Geteuid() != 0 {
		return errors.New("run this with sudo (it stops the services and replaces their data)")
	}
	var ids []age.Identity
	if *identity != "" {
		b, err := os.ReadFile(*identity)
		if err != nil {
			return err
		}
		if ids, err = backup.ParseIdentities(b); err != nil {
			return err
		}
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	m, files, err := backup.Read(f, ids)
	if err != nil {
		return err
	}
	sv, err := serverdb.LatestVersion()
	if err != nil {
		return err
	}
	ev, err := executordb.LatestVersion()
	if err != nil {
		return err
	}
	latest := map[string]int{"server": sv, "executor": ev}
	if err := backup.CheckSchemas(m, latest); err != nil {
		return err
	}
	fmt.Fprintln(w, "Restore this backup? (CRITICAL)")
	fmt.Fprintf(w, "  made         %s on %s by Nebula %s\n", displaySafe([]byte(m.CreatedAt), 40), displaySafe([]byte(m.Host), 64), displaySafe([]byte(m.Version), 40))
	fmt.Fprintf(w, "  schemas      server %d, executor %d (this Nebula: %d, %d)\n", m.Schemas["server"], m.Schemas["executor"], sv, ev)
	fmt.Fprintf(w, "  files        %d, checksums verified\n", len(files))
	fmt.Fprintln(w, "The services stop; the current data moves aside (kept as *.pre-restore-<time>); the backup's data takes its")
	fmt.Fprintln(w, "place; the configuration from the backup is written next to yours for review, not applied.")
	fmt.Fprint(w, "Type \"restore\" to continue: ")
	in := bufio.NewReader(stdin)
	line, _ := in.ReadString('\n')
	if strings.TrimSpace(line) != "restore" {
		return errors.New("not confirmed; nothing changed")
	}
	// A backup of another machine (a new machine, or the wrong file) takes
	// over that machine's inventory, event chain and keys: say so and ask
	// for its name (review m102, F2).
	if here, _ := hostname(); m.Host != here {
		fmt.Fprintf(w, "This backup was made on %s, not on this machine (%s). Restoring it here makes this machine take over\n",
			displaySafe([]byte(m.Host), 64), displaySafe([]byte(here), 64))
		fmt.Fprintln(w, "its inventory, history, event chain and SSH keys.")
		fmt.Fprint(w, "Type the backup's host name to continue: ")
		line, _ := in.ReadString('\n')
		if strings.TrimSpace(line) != m.Host || m.Host == "" {
			return errors.New("not confirmed; nothing changed")
		}
	}
	rep, err := backup.Restore(m, files, backup.Layout{Root: nebulaRoot}, sys, latest, now)
	if err != nil {
		return err
	}
	for _, d := range rep.MovedAside {
		fmt.Fprintf(w, "kept the previous data in %s\n", d)
	}
	for _, c := range rep.Config {
		fmt.Fprintf(w, "configuration from the backup, to compare: %s\n", c)
	}
	fmt.Fprintln(w, "restored; the executor starts locked: run nebula unlock (the SSH keys need their passphrase)")
	return nil
}
