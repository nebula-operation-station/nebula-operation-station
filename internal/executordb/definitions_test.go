// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	defIDA = "0f6c1b2a-3d4e-4f50-8a1b-2c3d4e5f6a7b"
	defIDB = "1f6c1b2a-3d4e-4f50-8a1b-2c3d4e5f6a7b"
)

// putDefinition adds the next version of host/name the way the executor
// does (metadata row and a stand-in sealed secret in one transaction).
func putDefinition(t *testing.T, db *DB, host, name, newID string) ContainerDefinition {
	t.Helper()
	d, err := db.NextContainerDefinition(host, name, newID)
	if err != nil {
		t.Fatal(err)
	}
	d.CreatedBy = "admin:uid0"
	stored, err := db.AddContainerDefinition(d, sealedSecret(d.VaultSecretID, 1))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// TestAddContainerDefinitionReturnsStoredRow: Put answers from what Add
// returns, so it must equal the row a later read gives.
func TestAddContainerDefinitionReturnsStoredRow(t *testing.T) {
	t1 := time.Date(2026, 11, 8, 10, 0, 0, 500, time.UTC)
	db := openAtT(t, privateDir(t), t1)
	stored := putDefinition(t, db, "web-1", "web", defIDA)
	vs, err := db.ContainerDefinitionVersions("web-1", "web")
	if err != nil || len(vs) != 1 {
		t.Fatalf("versions %+v %v", vs, err)
	}
	if stored != vs[0] || stored.CreatedAt.IsZero() {
		t.Fatalf("returned %+v, stored %+v", stored, vs[0])
	}
}

// sealedSecret is a stand-in encrypted secret of the sizes the vault
// table requires.
func sealedSecret(id string, version int64) VaultSecret {
	return VaultSecret{ID: id, Version: version, WrappedDEK: make([]byte, 72), Sealed: make([]byte, 40), UpdatedBy: "x"}
}

// standaloneRecreation writes a standalone recreation row whose recreation
// definition names definitionID at version, in state intent.
func standaloneRecreation(t *testing.T, db *DB, exec, definitionID string, version uint64) {
	t.Helper()
	r := recRow(exec)
	r.Form, r.Unit = "standalone", "web"
	r.Definition = fmt.Appendf(nil, `{"form":"standalone","definition_id":%q,"definition_version":%d,"services":[]}`, definitionID, version)
	if err := db.CreateContainerRecreation(r); err != nil {
		t.Fatal(err)
	}
}

func complete(t *testing.T, db *DB, exec string, at time.Time) {
	t.Helper()
	if err := db.CompleteContainerRecreation(exec, RecreationCompletion{State: RecreationRecreated}, at, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestDefinitionVersionKeptThroughWindow(t *testing.T) {
	t1 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	now := t1
	db := openAtT(t, privateDir(t), t1)
	db.now = func() time.Time { return now }
	v1 := putDefinition(t, db, "web-1", "web", defIDA)
	standaloneRecreation(t, db, recExec, v1.DefinitionID, v1.Version)
	// Put adds a version and keeps the previous one.
	v2 := putDefinition(t, db, "web-1", "web", defIDB)
	if v2.Version != 2 || v2.DefinitionID != v1.DefinitionID {
		t.Fatalf("second version %+v", v2)
	}
	vs, err := db.ContainerDefinitionVersions("web-1", "web")
	if err != nil || len(vs) != 2 || vs[0].Version != 1 || vs[1].Version != 2 {
		t.Fatalf("versions %+v %v", vs, err)
	}
	if _, err := db.GetSecret(v1.VaultSecretID); err != nil {
		t.Fatalf("previous version's secret is gone: %v", err)
	}
	// While the row is in intent and through its window, version 1 cannot
	// be dropped.
	if _, err := db.RemoveContainerDefinition("web-1", "web", 1, unlockedVault); !errors.Is(err, ErrDefinitionInWindow) {
		t.Fatalf("drop in intent: %v", err)
	}
	complete(t, db, recExec, t1)
	now = t1.Add(7*24*time.Hour - time.Second)
	if _, err := db.RemoveContainerDefinition("web-1", "web", 1, unlockedVault); !errors.Is(err, ErrDefinitionInWindow) {
		t.Fatalf("drop inside the window: %v", err)
	}
	if _, err := db.GetSecret(v1.VaultSecretID); err != nil {
		t.Fatalf("refused drop lost the secret: %v", err)
	}
	// After the window the old version may go, row and secret together.
	now = t1.Add(7*24*time.Hour + time.Second)
	dropped, err := db.RemoveContainerDefinition("web-1", "web", 1, unlockedVault)
	if err != nil || len(dropped) != 1 || dropped[0].Version != 1 {
		t.Fatalf("drop after the window: %+v %v", dropped, err)
	}
	if _, err := db.GetSecret(v1.VaultSecretID); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("dropped version's secret: %v", err)
	}
	if _, err := db.GetSecret(v2.VaultSecretID); err != nil {
		t.Fatalf("newest version's secret: %v", err)
	}
}

func TestDefinitionRemoveRefusedInsideWindow(t *testing.T) {
	t1 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	now := t1
	db := openAtT(t, privateDir(t), t1)
	db.now = func() time.Time { return now }
	v1 := putDefinition(t, db, "web-1", "web", defIDA)
	putDefinition(t, db, "web-1", "web", defIDA)
	// A row referencing the older version blocks removing the definition.
	standaloneRecreation(t, db, recExec, v1.DefinitionID, 1)
	if _, err := db.RemoveContainerDefinition("web-1", "web", 0, unlockedVault); !errors.Is(err, ErrDefinitionInWindow) {
		t.Fatalf("remove in intent: %v", err)
	}
	complete(t, db, recExec, t1)
	now = t1.Add(24 * time.Hour)
	if _, err := db.RemoveContainerDefinition("web-1", "web", 0, unlockedVault); !errors.Is(err, ErrDefinitionInWindow) {
		t.Fatalf("remove inside the window: %v", err)
	}
	if vs, err := db.ContainerDefinitionVersions("web-1", "web"); err != nil || len(vs) != 2 {
		t.Fatalf("refused remove changed versions: %+v %v", vs, err)
	}
	// The newest version alone is never dropped; remove the definition.
	if _, err := db.RemoveContainerDefinition("web-1", "web", 2, unlockedVault); !errors.Is(err, ErrDefinitionLatest) {
		t.Fatalf("drop newest: %v", err)
	}
	if _, err := db.RemoveContainerDefinition("web-1", "web", 9, unlockedVault); !errors.Is(err, ErrNoContainerDefinition) {
		t.Fatalf("drop unknown version: %v", err)
	}
	// A row of another definition does not block.
	const other = "00000000-0000-4000-9000-0000000000b2"
	standaloneRecreation(t, db, other, defIDB, 1)
	now = t1.Add(8 * 24 * time.Hour)
	dropped, err := db.RemoveContainerDefinition("web-1", "web", 0, unlockedVault)
	if err != nil || len(dropped) != 2 {
		t.Fatalf("remove after the window: %+v %v", dropped, err)
	}
	for _, d := range dropped {
		if _, err := db.GetSecret(d.VaultSecretID); !errors.Is(err, ErrNoSecret) {
			t.Fatalf("removed secret %s: %v", d.VaultSecretID, err)
		}
	}
	if _, err := db.ContainerDefinitionVersions("web-1", "web"); !errors.Is(err, ErrNoContainerDefinition) {
		t.Fatalf("after remove: %v", err)
	}
	if _, err := db.RemoveContainerDefinition("web-1", "web", 0, unlockedVault); !errors.Is(err, ErrNoContainerDefinition) {
		t.Fatalf("second remove: %v", err)
	}
}

// TestDefinitionWindowBlocksOnlyItsVersion: a recreation in its window
// pins the version it names, not every version of the definition.
func TestDefinitionWindowBlocksOnlyItsVersion(t *testing.T) {
	t1 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	now := t1
	db := openAtT(t, privateDir(t), t1)
	db.now = func() time.Time { return now }
	v1 := putDefinition(t, db, "web-1", "web", defIDA)
	v2 := putDefinition(t, db, "web-1", "web", defIDA)
	v3 := putDefinition(t, db, "web-1", "web", defIDA)
	// Only version 2 is referenced, in intent and then inside its window.
	standaloneRecreation(t, db, recExec, v2.DefinitionID, v2.Version)
	complete(t, db, recExec, t1)
	now = t1.Add(24 * time.Hour)
	if _, err := db.RemoveContainerDefinition("web-1", "web", v2.Version, unlockedVault); !errors.Is(err, ErrDefinitionInWindow) {
		t.Fatalf("drop the pinned version: %v", err)
	}
	dropped, err := db.RemoveContainerDefinition("web-1", "web", v1.Version, unlockedVault)
	if err != nil || len(dropped) != 1 || dropped[0].Version != v1.Version {
		t.Fatalf("drop an unpinned version: %+v %v", dropped, err)
	}
	if _, err := db.GetSecret(v1.VaultSecretID); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("dropped version's secret: %v", err)
	}
	for _, v := range []ContainerDefinition{v2, v3} {
		if _, err := db.GetSecret(v.VaultSecretID); err != nil {
			t.Fatalf("kept version %d lost its secret: %v", v.Version, err)
		}
	}
	// The whole definition still holds the pinned version, so it stays.
	if _, err := db.RemoveContainerDefinition("web-1", "web", 0, unlockedVault); !errors.Is(err, ErrDefinitionInWindow) {
		t.Fatalf("remove with a pinned version: %v", err)
	}
}

// errTestLocked stands in for the vault's locked error.
var errTestLocked = errors.New("test: vault locked")

// unlockedVault is the vault check of an executor that stays unlocked.
func unlockedVault() error { return nil }

// TestDefinitionRemoveRechecksVaultInsideTransaction: a vault lock that
// lands after the caller's own check still keeps every row and secret,
// because the remove re-checks the vault inside its transaction.
func TestDefinitionRemoveRechecksVaultInsideTransaction(t *testing.T) {
	db := openAtT(t, privateDir(t), time.Now())
	v1 := putDefinition(t, db, "web-1", "web", defIDA)
	v2 := putDefinition(t, db, "web-1", "web", defIDA)
	for _, version := range []uint64{0, v1.Version} {
		calls := 0
		_, err := db.RemoveContainerDefinition("web-1", "web", version, func() error { calls++; return errTestLocked })
		if !errors.Is(err, errTestLocked) || calls != 1 {
			t.Fatalf("remove %d with the vault locked: %v (%d checks)", version, err, calls)
		}
		for _, v := range []ContainerDefinition{v1, v2} {
			if _, err := db.GetSecret(v.VaultSecretID); err != nil {
				t.Fatalf("remove %d while locked lost version %d's secret: %v", version, v.Version, err)
			}
		}
		if vs, err := db.ContainerDefinitionVersions("web-1", "web"); err != nil || len(vs) != 2 {
			t.Fatalf("remove %d while locked changed versions: %+v %v", version, vs, err)
		}
	}
	// Without a check nothing is removed either.
	if _, err := db.RemoveContainerDefinition("web-1", "web", 0, nil); err == nil {
		t.Fatal("remove without a vault check accepted")
	}
	// A refusal that comes before any delete does not consult the vault.
	if _, err := db.RemoveContainerDefinition("web-1", "web", v2.Version, func() error {
		t.Fatal("vault checked for a refused remove")
		return nil
	}); !errors.Is(err, ErrDefinitionLatest) {
		t.Fatalf("drop newest: %v", err)
	}
	if _, err := db.RemoveContainerDefinition("web-1", "web", 0, unlockedVault); err != nil {
		t.Fatalf("remove with the vault unlocked: %v", err)
	}
}

func TestDefinitionIDSurvivesRecreate(t *testing.T) {
	t1 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	db := openAtT(t, privateDir(t), t1)
	v1 := putDefinition(t, db, "web-1", "web", defIDA)
	// The container is recreated (new container ID, same name); the next
	// version keeps the definition ID, whatever fresh ID the caller offers.
	standaloneRecreation(t, db, recExec, v1.DefinitionID, 1)
	complete(t, db, recExec, t1)
	v2 := putDefinition(t, db, "web-1", "web", defIDB)
	if v2.DefinitionID != defIDA || v2.Version != 2 {
		t.Fatalf("after recreate: %+v", v2)
	}
	// Another container on the same host gets its own ID.
	o := putDefinition(t, db, "web-1", "db", defIDB)
	if o.DefinitionID != defIDB || o.Version != 1 {
		t.Fatalf("other container: %+v", o)
	}
	// The database refuses a second ID for one container and one ID for
	// two containers.
	bad := ContainerDefinition{HostID: "web-1", ContainerName: "web", DefinitionID: defIDB, Version: 3,
		VaultSecretID: ContainerDefinitionSecretID(defIDB, 3), CreatedBy: "x"}
	if _, err := db.sql.Exec(`INSERT INTO container_definitions VALUES (?, ?, ?, ?, ?, ?, 0)`,
		bad.HostID, bad.ContainerName, bad.DefinitionID, bad.Version, bad.VaultSecretID, bad.CreatedBy); err == nil {
		t.Fatal("second definition ID for one container accepted")
	}
	if _, err := db.sql.Exec(`INSERT INTO container_definitions VALUES ('web-2', 'web', ?, 1, ?, 'x', 0)`,
		defIDA, ContainerDefinitionSecretID(defIDA, 1)); err == nil {
		t.Fatal("one definition ID for two containers accepted")
	}
}

func TestDefinitionSecretIDFitsVaultLimit(t *testing.T) {
	id := ContainerDefinitionSecretID("ffffffff-ffff-4fff-bfff-ffffffffffff", MaxContainerDefinitionVersion)
	if len(id) > 64 {
		t.Fatalf("longest secret ID has %d characters: %s", len(id), id)
	}
	db := openAtT(t, privateDir(t), time.Now())
	// The table accepts the longest ID and refuses a version above the
	// limit.
	if _, err := db.sql.Exec(`INSERT INTO container_definitions VALUES ('h', 'c', ?, ?, ?, 'x', 0)`,
		defIDA, int64(MaxContainerDefinitionVersion), ContainerDefinitionSecretID(defIDA, MaxContainerDefinitionVersion)); err != nil {
		t.Fatalf("longest version refused: %v", err)
	}
	if _, err := db.sql.Exec(`INSERT INTO container_definitions VALUES ('h', 'c', ?, ?, ?, 'x', 0)`,
		defIDA, int64(MaxContainerDefinitionVersion)+1, ContainerDefinitionSecretID(defIDA, MaxContainerDefinitionVersion+1)); err == nil {
		t.Fatal("version above the limit accepted")
	}
	// The next version after the limit is refused before anything is written.
	if _, err := db.NextContainerDefinition("h", "c", defIDB); !errors.Is(err, ErrDefinitionLimit) {
		t.Fatalf("version overflow: %v", err)
	}
}

func TestDefinitionVersionsAreWriteOnce(t *testing.T) {
	db := openAtT(t, privateDir(t), time.Now())
	v1 := putDefinition(t, db, "web-1", "web", defIDA)
	if _, err := db.sql.Exec(`UPDATE container_definitions SET created_by = 'y'`); err == nil {
		t.Fatal("update of a stored version accepted")
	}
	// Adding the same version again (a stale Next) is refused.
	sec := sealedSecret(v1.VaultSecretID, 1)
	v1.CreatedBy = "x"
	if _, err := db.AddContainerDefinition(v1, sec); !errors.Is(err, ErrSecretVersion) {
		t.Fatalf("stale add: %v", err)
	}
	// A vault secret that would replace an existing one is refused.
	next, err := db.NextContainerDefinition("web-1", "web", defIDB)
	if err != nil {
		t.Fatal(err)
	}
	next.CreatedBy = "x"
	if err := db.PutSecret(sealedSecret(next.VaultSecretID, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddContainerDefinition(next, sealedSecret(next.VaultSecretID, 2)); !errors.Is(err, ErrDefinitionExists) {
		t.Fatalf("replacing secret: %v", err)
	}
	if _, err := db.AddContainerDefinition(next, sealedSecret(next.VaultSecretID, 1)); !errors.Is(err, ErrDefinitionExists) {
		t.Fatalf("existing secret: %v", err)
	}
	if vs, _ := db.ContainerDefinitionVersions("web-1", "web"); len(vs) != 1 {
		t.Fatalf("refused adds stored versions: %+v", vs)
	}
	// A mismatched secret ID is refused.
	next.VaultSecretID = "ctrdef.other"
	if _, err := db.AddContainerDefinition(next, sec); err == nil {
		t.Fatal("mismatched secret ID accepted")
	}
}

func TestDefinitionVersionLimit(t *testing.T) {
	db := openAtT(t, privateDir(t), time.Now())
	for range MaxContainerDefinitionVersionsKept {
		putDefinition(t, db, "web-1", "web", defIDA)
	}
	d, err := db.NextContainerDefinition("web-1", "web", defIDA)
	if err != nil {
		t.Fatal(err)
	}
	d.CreatedBy = "x"
	if _, err := db.AddContainerDefinition(d, sealedSecret(d.VaultSecretID, 1)); !errors.Is(err, ErrDefinitionLimit) {
		t.Fatalf("version over the limit: %v", err)
	}
	if _, err := db.GetSecret(d.VaultSecretID); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("refused add wrote its secret: %v", err)
	}
}

func TestListContainerDefinitionsMetadataOnly(t *testing.T) {
	db := openAtT(t, privateDir(t), time.Now())
	putDefinition(t, db, "web-1", "web", defIDA)
	putDefinition(t, db, "web-2", "app", defIDB)
	all, err := db.ListContainerDefinitions("")
	if err != nil || len(all) != 2 {
		t.Fatalf("list all %+v %v", all, err)
	}
	one, err := db.ListContainerDefinitions("web-2")
	if err != nil || len(one) != 1 || one[0].ContainerName != "app" || !strings.HasPrefix(one[0].VaultSecretID, "ctrdef.") {
		t.Fatalf("list host %+v %v", one, err)
	}
}
