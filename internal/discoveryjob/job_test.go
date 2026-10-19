// SPDX-License-Identifier: AGPL-3.0-or-later

package discoveryjob

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00"

func job(mode Mode, targets ...string) Job {
	return Job{Format: JobFormat, ID: testID, Mode: mode, Targets: targets, CreatedAt: 1}
}

func TestArgs(t *testing.T) {
	base := []string{"--privileged", "-oX", "-", "--no-stylesheet", "--max-retries", "2", "--host-timeout", "10m"}
	ports := job(ModePorts, "192.168.10.0/24", "10.0.0.5")
	ports.Ports = "22,80,8000-8100"
	custom := job(ModeCustom, "fd00::/120")
	custom.Custom = &Custom{UDP: true, Ports: "53,161", Version: true, NoPing: true, OpenOnly: true, Timing: 4}
	for _, c := range []struct {
		j    Job
		want []string
	}{
		{job(ModePing, "192.168.10.7/24"), []string{"-sn", "-T3", "192.168.10.0/24"}},
		{ports, []string{"-sS", "-p", "22,80,8000-8100", "-T3", "192.168.10.0/24", "10.0.0.5"}},
		{job(ModeServices, "10.0.0.5/32"), []string{"-sS", "-sV", "--top-ports", "100", "-T3", "10.0.0.5"}},
		{job(ModeFullTCP, "10.0.0.0/16"), []string{"-sS", "-p-", "-T3", "10.0.0.0/16"}},
		{custom, []string{"-6", "-sS", "-sU", "-p", "T:53,161,U:53,161", "-sV", "-Pn", "--open", "-T4", "fd00::/120"}},
	} {
		got, err := c.j.Args()
		if err != nil {
			t.Fatal(c.j.Mode, err)
		}
		want := append(append([]string{}, base...), c.want...)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", c.j.Mode, got, want)
		}
	}
}

func TestValidateRefuses(t *testing.T) {
	ok := job(ModePing, "10.0.0.0/24")
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(j *Job)) Job { j := job(ModePing, "10.0.0.0/24"); f(&j); return j }
	for name, j := range map[string]Job{
		"format":        mut(func(j *Job) { j.Format = "x" }),
		"id":            mut(func(j *Job) { j.ID = "../../etc/passwd" }),
		"no targets":    mut(func(j *Job) { j.Targets = nil }),
		"option target": mut(func(j *Job) { j.Targets = []string{"-iL/etc/shadow"} }),
		"hostname":      mut(func(j *Job) { j.Targets = []string{"example.org"} }),
		"too large v4":  mut(func(j *Job) { j.Targets = []string{"10.0.0.0/15"} }),
		"too large v6":  mut(func(j *Job) { j.Targets = []string{"fd00::/64"} }),
		"mixed":         mut(func(j *Job) { j.Targets = []string{"10.0.0.1", "fd00::1"} }),
		"zone":          mut(func(j *Job) { j.Targets = []string{"fe80::1%eth0"} }),
		"total":         mut(func(j *Job) { j.Targets = []string{"10.0.0.0/16", "10.1.0.0/24"} }),
		"ping ports":    mut(func(j *Job) { j.Ports = "22" }),
		"ports bad":     mut(func(j *Job) { j.Mode, j.Ports = ModePorts, "22;id" }),
		"ports order":   mut(func(j *Job) { j.Mode, j.Ports = ModePorts, "80,22" }),
		"ports range":   mut(func(j *Job) { j.Mode, j.Ports = ModePorts, "100-10" }),
		"ports zero":    mut(func(j *Job) { j.Mode, j.Ports = ModePorts, "0" }),
		"custom none":   mut(func(j *Job) { j.Mode = ModeCustom }),
		"custom both":   mut(func(j *Job) { j.Mode, j.Custom = ModeCustom, &Custom{Ports: "22", TopPorts: 10} }),
		"custom udp":    mut(func(j *Job) { j.Mode, j.Custom = ModeCustom, &Custom{UDP: true} }),
		"custom timing": mut(func(j *Job) { j.Mode, j.Custom = ModeCustom, &Custom{Timing: 5} }),
		"custom top":    mut(func(j *Job) { j.Mode, j.Custom = ModeCustom, &Custom{TopPorts: 5000} }),
		"mode":          mut(func(j *Job) { j.Mode = "--script=x" }),
	} {
		if err := j.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
		if _, err := j.Args(); err == nil {
			t.Errorf("%s: args built", name)
		}
	}
	if p, err := NormalizePorts(" 443, 22,22,8000-8100 "); err != nil || p != "22,443,8000-8100" {
		t.Fatal(p, err)
	}
}

const sampleXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap">
<host><status state="up" reason="arp-response"/>
<address addr="192.168.10.21" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Synology &lt;script&gt;"/>
<hostnames><hostname name="NAS.lan." type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH&#x85;[31m" version="9.2p1&#x202e;"/></port>
<port protocol="tcp" portid="22"><state state="open"/></port>
<port protocol="sctp" portid="5"><state state="open"/></port>
<port protocol="tcp" portid="99999"><state state="open"/></port>
<port protocol="tcp" portid="80"><state state="weird"/></port>
</ports>
<os><osmatch name="Linux 5.X" accuracy="95"/></os>
</host>
<host><status state="down"/><address addr="192.168.10.22" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="192.168.10.23" addrtype="ipv4"/><hostnames><hostname name="evil host;rm -rf" type="PTR"/></hostnames></host>
<host><status state="up"/><address addr="not-an-ip" addrtype="ipv4"/></host>
<runstats><finished exit="success"/></runstats>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	hosts, err := ParseNmapXML(strings.NewReader(sampleXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("%+v", hosts)
	}
	h := hosts[0]
	if h.Address != "192.168.10.21" || h.MAC != "aa:bb:cc:dd:ee:ff" || h.Hostname != "nas.lan" || h.OS != "Linux 5.X" || h.Vendor != "Synology <script>" {
		t.Fatalf("%+v", h)
	}
	if len(h.Ports) != 2 || h.Ports[0].Port != 22 || h.Ports[1].State != "unknown" {
		t.Fatalf("%+v", h.Ports)
	}
	if strings.ContainsAny(h.Ports[0].Product+h.Ports[0].Version, "\u0085\u202e") {
		t.Fatalf("control characters kept: %q %q", h.Ports[0].Product, h.Ports[0].Version)
	}
	if hosts[1].Hostname != "" {
		t.Fatalf("bad hostname kept: %q", hosts[1].Hostname)
	}
	if _, err := ParseNmapXML(strings.NewReader(`<!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun><host>&a;</host></nmaprun>`)); err == nil {
		t.Fatal("entity accepted")
	}
	if _, err := ParseNmapXML(strings.NewReader(`<nmaprun><runstats><finished exit="error" errormsg="boom"/></runstats></nmaprun>`)); err == nil {
		t.Fatal("nmap error ignored")
	}
}

func TestSpool(t *testing.T) {
	dir := t.TempDir()
	s := Spool{Dir: dir}
	if s.Available() {
		t.Fatal("available without jobs dir")
	}
	for _, d := range []string{s.JobsDir(), s.ResultsDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	j := job(ModePing, "10.0.0.0/24")
	if err := s.WriteJob(j); err != nil {
		t.Fatal(err)
	}
	bad := job(ModePing, "10.0.0.0/8")
	if err := s.WriteJob(bad); err == nil {
		t.Fatal("invalid job written")
	}
	// A hand-written invalid job and a symlinked one.
	other := "11111111-2222-4333-8444-555555555555"
	_ = os.WriteFile(filepath.Join(s.JobsDir(), other+".json"), []byte(`{"format":"`+JobFormat+`","id":"`+other+`","mode":"ping","targets":["0.0.0.0/0"],"created_at":1}`), 0o640)
	link := "22222222-2222-4333-8444-555555555555"
	_ = os.Symlink("/etc/passwd", filepath.Join(s.JobsDir(), link+".json"))
	_ = os.WriteFile(filepath.Join(s.JobsDir(), "notes.txt"), []byte("x"), 0o640)
	jobs, badJobs, err := s.PendingJobs()
	if err != nil || len(jobs) != 1 || jobs[0].ID != testID || len(badJobs) != 2 || badJobs[other] == nil || badJobs[link] == nil {
		t.Fatalf("%v %v %v", jobs, badJobs, err)
	}
	if _, err := s.ReadResult(testID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	r := Result{Format: ResultFormat, Job: testID, StartedAt: 1, FinishedAt: 2, OK: true,
		Hosts: []Host{{Address: "10.0.0.9"}, {Address: "10.0.0.2", Hostname: "A.example."}, {Address: "10.0.0.9"}, {Address: "x"}}}
	if err := s.WriteResult(r); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadResult(testID)
	if err != nil || len(got.Hosts) != 2 || got.Hosts[0].Address != "10.0.0.2" || got.Hosts[0].Hostname != "a.example" {
		t.Fatalf("%+v %v", got, err)
	}
	if jobs, _, _ := s.PendingJobs(); len(jobs) != 0 {
		t.Fatal("job with a result still pending")
	}
	// A result whose job field names another job is refused.
	_ = os.WriteFile(filepath.Join(s.ResultsDir(), other+".json"), []byte(`{"format":"`+ResultFormat+`","job":"`+testID+`","started_at":1,"finished_at":1,"ok":true,"hosts":[]}`), 0o640)
	if _, err := s.ReadResult(other); err == nil {
		t.Fatal("result for another job accepted")
	}
	if err := s.RemoveJob(testID); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveJob("../x"); err == nil {
		t.Fatal("path accepted")
	}
	s.PruneResults(time.Hour, time.Now().Add(2*time.Hour))
	if _, err := os.Stat(filepath.Join(s.ResultsDir(), testID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old result kept")
	}
}
