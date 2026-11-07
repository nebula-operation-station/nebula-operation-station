// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func h64(c string) string { return strings.Repeat(c, 64) }
func dg(c string) string  { return "sha256:" + h64(c) }

// composeUpdate is a valid compose update: app changes its tag (HIGH), worker
// is a same-tag refresh, db is a frozen dependency.
func composeUpdate() BatchContainerUpdate {
	return BatchContainerUpdate{
		Kind: ContainerUpdateKindUpdate,
		Form: ContainerUpdateFormCompose,
		Images: []ContainerUpdateImage{
			{Service: "app", Repository: "docker.io/library/nginx", Platform: "linux/amd64", OldTag: "1.27", NewTag: "1.28",
				OldDigests: []string{dg("1")}, NewIndexDigest: dg("2"), NewPlatformDigest: dg("3"), OldImageID: dg("4"),
				PolicyVersion: "stable-v1", PolicyDigest: h64("5")},
			{Service: "worker", Repository: "ghcr.io/acme/worker", Platform: "linux/arm64/v8", OldTag: "latest", NewTag: "latest",
				OldDigests: []string{dg("6"), dg("7")}, NewPlatformDigest: dg("8"), OldImageID: dg("9")},
		},
		Targets: []ContainerUpdateTarget{
			{Service: "app", ContainerID: h64("a"), ContainerName: "shop-app-1", ImageID: dg("4"), RunningReference: "nginx:1.27", ConfigurationDigest: h64("b")},
			{Service: "app", ContainerID: h64("c"), ContainerName: "shop-app-2", ImageID: dg("4"), RunningReference: "docker.io/library/nginx:1.27@" + dg("1"), ConfigurationDigest: h64("d")},
			{Service: "worker", ContainerID: h64("e"), ContainerName: "shop-worker-1", ImageID: dg("9"), RunningReference: "ghcr.io/acme/worker", ConfigurationDigest: h64("f")},
		},
		Dependencies: []ContainerUpdateDependency{
			{Service: "db", Relation: ContainerDependencyRequires, Containers: []ContainerDependencyMember{{ContainerID: h64("0"), ContainerName: "shop-db-1", ConfigurationDigest: h64("1")}}},
		},
		SourceDigest: h64("2"), Project: "shop", WorkingDirHash: h64("3"), ConfigFilesHash: h64("4"),
	}
}

// composeRollback returns app to 1.27; one entry has no target (missing).
func composeRollback() BatchContainerUpdate {
	u := composeUpdate()
	u.Kind = ContainerUpdateKindRollback
	u.RollbackOf = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a77"
	u.RecoveryPlanDigest = h64("6")
	for i := range u.Images {
		img := &u.Images[i]
		img.OldTag, img.NewTag = img.NewTag, img.OldTag
		img.OldDigests = []string{img.NewPlatformDigest}
		img.NewIndexDigest, img.NewPlatformDigest, img.OldImageID = "", "", ""
		img.Rollback = &ContainerRollbackImage{PriorImageID: dg("4"), RetainedTag: "nos-retained-1", RetainedReference: img.Repository + ":nos-retained-1"}
	}
	u.Targets = u.Targets[:2] // worker is recorded as missing
	u.Targets[1].RunningReference = "docker.io/library/nginx:1.28@" + dg("3")
	u.Targets[1].ImageID = dg("a")
	return u
}

func standaloneUpdate() BatchContainerUpdate {
	return BatchContainerUpdate{
		Kind: ContainerUpdateKindUpdate, Form: ContainerUpdateFormAlone,
		Images: []ContainerUpdateImage{{Repository: "docker.io/library/redis", Platform: "linux/amd64", OldTag: "7", NewTag: "7",
			OldDigests: []string{dg("1")}, NewPlatformDigest: dg("2"), OldImageID: dg("3")}},
		Targets:           []ContainerUpdateTarget{{ContainerID: h64("a"), ContainerName: "redis", ImageID: dg("3"), RunningReference: "redis:7", ConfigurationDigest: h64("b")}},
		Dependencies:      []ContainerUpdateDependency{},
		DefinitionID:      "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a55",
		DefinitionVersion: 3,
	}
}

// cuBatch is a one-member batch for action with binding u and the rendered
// parameters hash.
func cuBatch(t *testing.T, action string, u BatchContainerUpdate) Batch {
	t.Helper()
	b := batchFixture(1)
	m := &b.Members[0]
	m.Request.ActionID = action
	m.ContainerUpdate = &u
	if _, hash, err := ContainerUpdateParameters(u); err == nil {
		m.Request.ParametersHash = hash
	}
	return b
}

func TestContainerUpdateBindingsAccepted(t *testing.T) {
	cases := map[string]struct {
		action string
		u      BatchContainerUpdate
	}{
		"compose update":    {"docker.compose_update", composeUpdate()},
		"compose rollback":  {"docker.compose_rollback", composeRollback()},
		"standalone update": {"docker.update", standaloneUpdate()},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := CanonicalizeBatch(cuBatch(t, c.action, c.u), testNow); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMalformedContainerUpdateBindingRefused(t *testing.T) {
	cases := map[string]func(*BatchContainerUpdate){
		"short container id":       func(u *BatchContainerUpdate) { u.Targets[0].ContainerID = h64("a")[:12] },
		"uppercase container id":   func(u *BatchContainerUpdate) { u.Targets[0].ContainerID = strings.ToUpper(h64("a")) },
		"leading dash in name":     func(u *BatchContainerUpdate) { u.Targets[0].ContainerName = "-app" },
		"name with slash":          func(u *BatchContainerUpdate) { u.Targets[0].ContainerName = "/app" },
		"digest shape":             func(u *BatchContainerUpdate) { u.Images[0].NewPlatformDigest = "sha512:" + h64("3") },
		"image id shape":           func(u *BatchContainerUpdate) { u.Targets[0].ImageID = h64("4") },
		"config digest shape":      func(u *BatchContainerUpdate) { u.Targets[0].ConfigurationDigest = "x" },
		"duplicate target":         func(u *BatchContainerUpdate) { u.Targets[1] = u.Targets[0] },
		"duplicate container name": func(u *BatchContainerUpdate) { u.Targets[1].ContainerName = u.Targets[0].ContainerName },
		"container in target and dependency": func(u *BatchContainerUpdate) {
			u.Dependencies[0].Containers[0].ContainerID = u.Targets[0].ContainerID
		},
		"unsorted targets": func(u *BatchContainerUpdate) { u.Targets[0], u.Targets[1] = u.Targets[1], u.Targets[0] },
		"unsorted images":  func(u *BatchContainerUpdate) { u.Images[0], u.Images[1] = u.Images[1], u.Images[0] },
		"target without image entry": func(u *BatchContainerUpdate) {
			u.Targets[2].Service = "zzz"
		},
		"entry without target on update": func(u *BatchContainerUpdate) { u.Targets = u.Targets[:2] },
		"second entry for one service": func(u *BatchContainerUpdate) {
			u.Images[1].Service = "app"
		},
		"no-op same-tag entry, platform digest": func(u *BatchContainerUpdate) { u.Images[1].NewPlatformDigest = dg("7") },
		"no-op same-tag entry, index digest":    func(u *BatchContainerUpdate) { u.Images[1].NewIndexDigest = dg("6") },
		"empty old_digests":                     func(u *BatchContainerUpdate) { u.Images[0].OldDigests = []string{} },
		"unsorted old_digests":                  func(u *BatchContainerUpdate) { u.Images[1].OldDigests = []string{dg("7"), dg("6")} },
		"policy missing on tag change":          func(u *BatchContainerUpdate) { u.Images[0].PolicyVersion = "" },
		"policy digest missing on tag change":   func(u *BatchContainerUpdate) { u.Images[0].PolicyDigest = "" },
		"policy set on same-tag entry": func(u *BatchContainerUpdate) {
			u.Images[1].PolicyVersion = "stable-v1"
			u.Images[1].PolicyDigest = h64("5")
		},
		"major change on same-tag entry": func(u *BatchContainerUpdate) { u.Images[1].MajorChange = true },
		"rollback block on update": func(u *BatchContainerUpdate) {
			u.Images[0].Rollback = &ContainerRollbackImage{PriorImageID: dg("4"), RetainedTag: "x", RetainedReference: "nginx:x"}
		},
		"update without new_platform_digest": func(u *BatchContainerUpdate) { u.Images[0].NewPlatformDigest = "" },
		"update without old_image_id":        func(u *BatchContainerUpdate) { u.Images[0].OldImageID = "" },
		"index equals platform digest":       func(u *BatchContainerUpdate) { u.Images[0].NewIndexDigest = u.Images[0].NewPlatformDigest },
		"rollback_of on update":              func(u *BatchContainerUpdate) { u.RollbackOf = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a77" },
		"definition on compose": func(u *BatchContainerUpdate) {
			u.DefinitionID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a55"
			u.DefinitionVersion = 1
		},
		"missing source_digest":              func(u *BatchContainerUpdate) { u.SourceDigest = "" },
		"missing project":                    func(u *BatchContainerUpdate) { u.Project = "" },
		"uppercase project":                  func(u *BatchContainerUpdate) { u.Project = "Shop" },
		"malformed dependency relation":      func(u *BatchContainerUpdate) { u.Dependencies[0].Relation = "needs" },
		"service in images and dependencies": func(u *BatchContainerUpdate) { u.Dependencies[0].Service = "worker" },
		"dependency without containers":      func(u *BatchContainerUpdate) { u.Dependencies[0].Containers = []ContainerDependencyMember{} },
		"repository not canonical":           func(u *BatchContainerUpdate) { u.Images[0].Repository = "nginx" },
		"repository uppercase":               func(u *BatchContainerUpdate) { u.Images[0].Repository = "docker.io/library/Nginx" },
		"malformed platform":                 func(u *BatchContainerUpdate) { u.Images[0].Platform = "amd64" },
		"empty tag":                          func(u *BatchContainerUpdate) { u.Images[1].NewTag = "" },
		"mixed replica images (TestUpdateRefusesMixedReplicaImages)": func(u *BatchContainerUpdate) {
			u.Targets[1].ImageID = dg("e")
		},
		"running reference other tag (TestRunningReferenceMustMatchOldTag)": func(u *BatchContainerUpdate) {
			u.Targets[0].RunningReference = "nginx:1.28"
		},
		"running reference implicit latest vs tag": func(u *BatchContainerUpdate) { u.Targets[0].RunningReference = "nginx" },
		"running reference other repository":       func(u *BatchContainerUpdate) { u.Targets[0].RunningReference = "library/httpd:1.27" },
		"running reference digest only":            func(u *BatchContainerUpdate) { u.Targets[0].RunningReference = "nginx@" + dg("1") },
		"too many images": func(u *BatchContainerUpdate) {
			for i := len(u.Images); i <= maxContainerUpdateImages; i++ {
				img := u.Images[1]
				img.Service = "w" + strings.Repeat("x", i)
				u.Images = append(u.Images, img)
				tg := u.Targets[2]
				tg.Service = img.Service
				tg.ContainerID = strings.Repeat("e", 62) + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16])
				tg.ContainerName = "w-" + tg.ContainerID[62:]
				u.Targets = append(u.Targets, tg)
			}
		},
		"too many containers": func(u *BatchContainerUpdate) {
			d := &u.Dependencies[0]
			d.Containers = nil
			for i := 0; i < maxContainerUpdateContainers; i++ {
				id := strings.Repeat("0", 60) + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16]) + "00"
				d.Containers = append(d.Containers, ContainerDependencyMember{ContainerID: id, ContainerName: "db-" + id[60:62], ConfigurationDigest: h64("1")})
			}
		},
		"no targets": func(u *BatchContainerUpdate) { u.Targets = []ContainerUpdateTarget{} },
		"malformed registry": func(u *BatchContainerUpdate) {
			u.Registry = &ContainerUpdateRegistry{RegistryID: "ghcr", RecordDigest: h64("1"), CredentialID: "ghcr-ci"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			u := composeUpdate()
			mutate(&u)
			if _, _, _, err := CanonicalizeBatch(cuBatch(t, "docker.compose_update", u), testNow); err == nil {
				t.Fatal("malformed binding accepted")
			}
		})
	}
}

func TestStandaloneBindingShape(t *testing.T) {
	cases := map[string]func(*BatchContainerUpdate){
		"source_digest on standalone (Q20)": func(u *BatchContainerUpdate) { u.SourceDigest = h64("2") },
		"project on standalone":             func(u *BatchContainerUpdate) { u.Project = "x" },
		"missing definition":                func(u *BatchContainerUpdate) { u.DefinitionID = "" },
		"zero definition version":           func(u *BatchContainerUpdate) { u.DefinitionVersion = 0 },
		"service name on standalone":        func(u *BatchContainerUpdate) { u.Images[0].Service = "x"; u.Targets[0].Service = "x" },
		"two containers": func(u *BatchContainerUpdate) {
			t2 := u.Targets[0]
			t2.ContainerID, t2.ContainerName = h64("c"), "redis2"
			u.Targets = append(u.Targets, t2)
		},
		"dependency on standalone": func(u *BatchContainerUpdate) {
			u.Dependencies = []ContainerUpdateDependency{{Service: "db", Relation: ContainerDependencyRequires, Containers: []ContainerDependencyMember{{ContainerID: h64("0"), ContainerName: "db", ConfigurationDigest: h64("1")}}}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			u := standaloneUpdate()
			mutate(&u)
			if _, _, _, err := CanonicalizeBatch(cuBatch(t, "docker.update", u), testNow); err == nil {
				t.Fatal("malformed standalone binding accepted")
			}
		})
	}
}

func TestRollbackEntryMayHaveNoTarget(t *testing.T) {
	u := composeRollback()
	if _, _, _, err := CanonicalizeBatch(cuBatch(t, "docker.compose_rollback", u), testNow); err != nil {
		t.Fatalf("rollback with a missing service refused: %v", err)
	}
	up := composeUpdate()
	up.Targets = up.Targets[:2]
	if _, _, _, err := CanonicalizeBatch(cuBatch(t, "docker.compose_update", up), testNow); err == nil {
		t.Fatal("update entry without a target accepted")
	}
}

func TestMalformedRollbackBindingRefused(t *testing.T) {
	cases := map[string]func(*BatchContainerUpdate){
		"missing rollback block":       func(u *BatchContainerUpdate) { u.Images[0].Rollback = nil },
		"missing rollback_of":          func(u *BatchContainerUpdate) { u.RollbackOf = "" },
		"missing recovery plan":        func(u *BatchContainerUpdate) { u.RecoveryPlanDigest = "" },
		"new digest on rollback":       func(u *BatchContainerUpdate) { u.Images[0].NewPlatformDigest = dg("3") },
		"old_image_id on rollback":     func(u *BatchContainerUpdate) { u.Images[0].OldImageID = dg("3") },
		"retained reference elsewhere": func(u *BatchContainerUpdate) { u.Images[0].Rollback.RetainedReference = "httpd:1" },
		"malformed prior image":        func(u *BatchContainerUpdate) { u.Images[0].Rollback.PriorImageID = "4" },
		"policy missing on reversal":   func(u *BatchContainerUpdate) { u.Images[0].PolicyDigest = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			u := composeRollback()
			mutate(&u)
			if _, _, _, err := CanonicalizeBatch(cuBatch(t, "docker.compose_rollback", u), testNow); err == nil {
				t.Fatal("malformed rollback binding accepted")
			}
		})
	}
}

func TestContainerActionRequiresUpdateBinding(t *testing.T) {
	for _, action := range []string{"docker.compose_update", "docker.compose_rollback", "docker.update", "docker.rollback"} {
		t.Run(action+"/none", func(t *testing.T) {
			b := cuBatch(t, action, composeUpdate())
			b.Members[0].ContainerUpdate = nil
			if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
				t.Fatal("container update action without binding accepted")
			}
		})
		t.Run(action+"/container instead", func(t *testing.T) {
			b := cuBatch(t, action, composeUpdate())
			b.Members[0].ContainerUpdate = nil
			b.Members[0].Container = &BatchContainer{ContainerID: h64("a"), ConfigurationHash: h64("b"), OldImageDigest: dg("1"), NewImageDigest: dg("2")}
			if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
				t.Fatal("container update action with an incarnation binding accepted")
			}
		})
		t.Run(action+"/both", func(t *testing.T) {
			b := cuBatch(t, "docker.compose_update", composeUpdate())
			b.Members[0].Container = &BatchContainer{ContainerID: h64("a"), ConfigurationHash: h64("b"), OldImageDigest: dg("1"), NewImageDigest: dg("2")}
			if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
				t.Fatal("member with both bindings accepted")
			}
		})
	}
}

func TestContainerActionFixesKindAndForm(t *testing.T) {
	actions := map[string][2]string{
		"docker.compose_update":   {ContainerUpdateKindUpdate, ContainerUpdateFormCompose},
		"docker.compose_rollback": {ContainerUpdateKindRollback, ContainerUpdateFormCompose},
		"docker.update":           {ContainerUpdateKindUpdate, ContainerUpdateFormAlone},
		"docker.rollback":         {ContainerUpdateKindRollback, ContainerUpdateFormAlone},
	}
	wrong := 0
	for action, want := range actions {
		for _, kind := range []string{ContainerUpdateKindUpdate, ContainerUpdateKindRollback} {
			for _, form := range []string{ContainerUpdateFormCompose, ContainerUpdateFormAlone} {
				if kind == want[0] && form == want[1] {
					continue
				}
				wrong++
				// Start from a binding valid for the requested kind and form,
				// so only the action table can refuse it.
				var u BatchContainerUpdate
				switch {
				case form == ContainerUpdateFormCompose && kind == ContainerUpdateKindUpdate:
					u = composeUpdate()
				case form == ContainerUpdateFormCompose:
					u = composeRollback()
				default:
					u = standaloneUpdate()
					u.Kind = kind
				}
				if _, _, _, err := CanonicalizeBatch(cuBatch(t, action, u), testNow); err == nil {
					t.Errorf("%s accepted kind=%s form=%s", action, kind, form)
				}
			}
		}
	}
	if wrong != 12 {
		t.Fatalf("checked %d wrong combinations, want 12", wrong)
	}
}

func TestUpdateBindingRefusedOnOtherAction(t *testing.T) {
	for _, action := range []string{"docker.restart", "docker.stop", "docker.start", "patching.install_security", "docker.compose_up"} {
		b := cuBatch(t, action, composeUpdate())
		if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
			t.Errorf("%s accepted a container update binding", action)
		}
	}
}

func TestContainerBindingDiffersFromParametersRefused(t *testing.T) {
	b := cuBatch(t, "docker.compose_update", composeUpdate())
	b.Members[0].Request.ParametersHash = h64("b")
	if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
		t.Fatal("parameters_hash not rendered from the binding accepted")
	}
	// The rendering of another binding does not fit either.
	other := composeUpdate()
	other.Targets[0].ConfigurationDigest = h64("9")
	_, hash, err := ContainerUpdateParameters(other)
	if err != nil {
		t.Fatal(err)
	}
	b.Members[0].Request.ParametersHash = hash
	if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
		t.Fatal("parameters of a different binding accepted")
	}
}

func TestDockerUpdateLeftIncarnationBindingList(t *testing.T) {
	b := cuBatch(t, "docker.update", standaloneUpdate())
	if _, _, _, err := CanonicalizeBatch(b, testNow); err != nil {
		t.Fatalf("docker.update with only its update binding refused: %v", err)
	}
}

func TestContainerUpdateEveryBindingChangesDigest(t *testing.T) {
	_, _, base, err := CanonicalizeBatch(cuBatch(t, "docker.compose_update", composeUpdate()), testNow)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*BatchContainerUpdate){
		"source digest": func(u *BatchContainerUpdate) { u.SourceDigest = h64("9") },
		"project":       func(u *BatchContainerUpdate) { u.Project = "shop2" },
		"working dir":   func(u *BatchContainerUpdate) { u.WorkingDirHash = h64("9") },
		"config files":  func(u *BatchContainerUpdate) { u.ConfigFilesHash = h64("9") },
		"repository": func(u *BatchContainerUpdate) {
			u.Images[1].Repository = "ghcr.io/acme/worker2"
			u.Targets[2].RunningReference = "ghcr.io/acme/worker2"
		},
		"platform": func(u *BatchContainerUpdate) { u.Images[0].Platform = "linux/arm64" },
		"old tag": func(u *BatchContainerUpdate) {
			u.Images[0].OldTag = "1.26"
			u.Targets[0].RunningReference = "nginx:1.26"
			u.Targets[1].RunningReference = "nginx:1.26"
		},
		"new tag":             func(u *BatchContainerUpdate) { u.Images[0].NewTag = "1.29" },
		"old digests":         func(u *BatchContainerUpdate) { u.Images[0].OldDigests = []string{dg("0")} },
		"new index digest":    func(u *BatchContainerUpdate) { u.Images[0].NewIndexDigest = dg("e") },
		"new platform digest": func(u *BatchContainerUpdate) { u.Images[0].NewPlatformDigest = dg("e") },
		"old image id":        func(u *BatchContainerUpdate) { u.Images[1].OldImageID = dg("e"); u.Targets[2].ImageID = dg("e") },
		"policy version":      func(u *BatchContainerUpdate) { u.Images[0].PolicyVersion = "stable-v2" },
		"policy digest":       func(u *BatchContainerUpdate) { u.Images[0].PolicyDigest = h64("e") },
		"major change":        func(u *BatchContainerUpdate) { u.Images[0].MajorChange = true },
		"container id":        func(u *BatchContainerUpdate) { u.Targets[2].ContainerID = h64("9") },
		"container name":      func(u *BatchContainerUpdate) { u.Targets[0].ContainerName = "shop-app-9" },
		"running reference":   func(u *BatchContainerUpdate) { u.Targets[0].RunningReference = "docker.io/library/nginx:1.27" },
		"configuration":       func(u *BatchContainerUpdate) { u.Targets[1].ConfigurationDigest = h64("9") },
		"dependency relation": func(u *BatchContainerUpdate) { u.Dependencies[0].Relation = ContainerDependencyRequiredBy },
		"dependency restart":  func(u *BatchContainerUpdate) { u.Dependencies[0].RestartOnUpdate = true },
		"dependency service":  func(u *BatchContainerUpdate) { u.Dependencies[0].Service = "cache" },
		"dependency container": func(u *BatchContainerUpdate) {
			u.Dependencies[0].Containers[0].ContainerID = h64("8")
		},
		"dependency container config": func(u *BatchContainerUpdate) { u.Dependencies[0].Containers[0].ConfigurationDigest = h64("8") },
		"dependency removed":          func(u *BatchContainerUpdate) { u.Dependencies = []ContainerUpdateDependency{} },
		"registry": func(u *BatchContainerUpdate) {
			u.Registry = &ContainerUpdateRegistry{RegistryID: "ghcr", RecordDigest: h64("1"), CredentialID: "ghcr-ci", CredentialVersion: 1}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			u := composeUpdate()
			mutate(&u)
			_, _, d, err := CanonicalizeBatch(cuBatch(t, "docker.compose_update", u), testNow)
			if err != nil {
				t.Fatal(err)
			}
			if d == base {
				t.Fatal("binding change kept the plan digest")
			}
		})
	}
}

func TestContainerUpdateGolden(t *testing.T) {
	b := cuBatch(t, "docker.compose_update", composeUpdate())
	n, got, d, err := CanonicalizeBatch(b, testNow)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/batch-v1-container-update.json")
	if err != nil {
		t.Fatal(err)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes changed:\ngot %s", got)
	}
	const wantDigest = "388c05aad6efb8e8d3b391246dc1290416a6b4e136020cebf16bd1c12cbdca98"
	if d.String() != wantDigest {
		t.Fatalf("digest = %s", d)
	}
	parsed, back, backDigest, err := ParseBatch(got, testNow)
	if err != nil || !bytes.Equal(back, got) || backDigest != d || !reflect.DeepEqual(parsed, n) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestContainerUpdateUnknownOrNullKeyRefused(t *testing.T) {
	_, raw, _, err := CanonicalizeBatch(cuBatch(t, "docker.compose_update", composeUpdate()), testNow)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][2]string{
		"unknown key in binding": {`"form":"compose"`, `"form":"compose","extra":1`},
		"unknown key in target":  {`"container_name":"shop-app-1"`, `"container_name":"shop-app-1","privileged":true`},
		"unknown key in image":   {`"platform":"linux/amd64"`, `"platform":"linux/amd64","pull":"always"`},
		"null dependencies":      {`"dependencies":[{`, `"dependencies":null,"x":[{`},
		"case alias":             {`"kind":"update"`, `"Kind":"update"`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if !bytes.Contains(raw, []byte(c[0])) {
				t.Fatalf("fixture lacks %s", c[0])
			}
			mod := bytes.Replace(raw, []byte(c[0]), []byte(c[1]), 1)
			if _, _, _, err := ParseBatch(mod, testNow); err == nil {
				t.Fatal("modified binding accepted")
			}
		})
	}
}

func TestContainerUpdateFloor(t *testing.T) {
	u := composeUpdate()
	if got := ContainerUpdateFloor(u); got != RiskHigh {
		t.Fatalf("one tag change among several entries = %s, want HIGH", got)
	}
	u.Images = u.Images[1:]
	if got := ContainerUpdateFloor(u); got != RiskMedium {
		t.Fatalf("same-tag refresh = %s, want MEDIUM", got)
	}
	r := composeRollback()
	if got := ContainerUpdateFloor(r); got != RiskHigh {
		t.Fatalf("tag reversal = %s, want HIGH", got)
	}
}

func TestContainerUpdateParametersRenderEveryScriptValue(t *testing.T) {
	raw, _, err := ContainerUpdateParameters(composeRollback())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	cu := doc["container_update"]
	for _, want := range []string{"running_reference", "retained_reference", "prior_image_id", "rollback_of"} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("rendering lacks %s", want)
		}
	}
	if cu["kind"] != "rollback" {
		t.Fatalf("kind = %v", cu["kind"])
	}
}

func TestParseImageReference(t *testing.T) {
	ok := map[string]ImageReference{
		"nginx":                        {"docker.io/library/nginx", "latest", ""},
		"nginx:1.27":                   {"docker.io/library/nginx", "1.27", ""},
		"library/nginx":                {"docker.io/library/nginx", "latest", ""},
		"docker.io/nginx:1":            {"docker.io/library/nginx", "1", ""},
		"docker.io/library/nginx:1":    {"docker.io/library/nginx", "1", ""},
		"index.docker.io/a/b:1":        {"docker.io/a/b", "1", ""},
		"index.docker.io/nginx":        {"docker.io/library/nginx", "latest", ""},
		"acme/app:2":                   {"docker.io/acme/app", "2", ""},
		"ghcr.io/a/b:1":                {"ghcr.io/a/b", "1", ""},
		"localhost:5000/a:1":           {"localhost:5000/a", "1", ""},
		"localhost/a":                  {"localhost/a", "latest", ""},
		"registry.lan:8443/x/y-z:v1.0": {"registry.lan:8443/x/y-z", "v1.0", ""},
		"nginx:1.27@" + dg("1"):        {"docker.io/library/nginx", "1.27", dg("1")},
	}
	for in, want := range ok {
		got, err := ParseImageReference(in)
		if err != nil || got != want {
			t.Errorf("ParseImageReference(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	bad := []string{
		"", "nginx@" + dg("1"), dg("1"), h64("a"), "Nginx", "docker.io/Library/nginx", "nginx:", "-nginx",
		"nginx:1.27@sha256:abc", "ghcr.io/a/b:1 ", "ghcr.io/a//b", "nginx:" + strings.Repeat("a", 129),
		"ghcr.io/" + strings.Repeat("a/", 130) + "b", "nginx:tag\n", "ngïnx",
	}
	for _, in := range bad {
		if got, err := ParseImageReference(in); !errors.Is(err, ErrImageReference) {
			t.Errorf("ParseImageReference(%q) = %+v, %v; want refusal", in, got, err)
		}
	}
}

func TestBatchOnlyContainerActions(t *testing.T) {
	for _, id := range []string{"docker.update", "docker.rollback", "docker.compose_rollback"} {
		if !IsBatchOnlyContainerAction(id) {
			t.Errorf("%s is not batch-only", id)
		}
	}
	// docker.compose_update 1.0.0 stays a classic action until cu02.
	for _, id := range []string{"docker.compose_update", "docker.restart", "docker.check_updates"} {
		if IsBatchOnlyContainerAction(id) {
			t.Errorf("%s is batch-only", id)
		}
	}
}
