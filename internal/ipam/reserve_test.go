// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
)

func TestReserveFreeAddressReturnsBindableReservation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, nil)
	lan(t, s)
	r, err := s.Reserve(ctx, "admin", "lan", "servers", addr("192.168.10.12"), "provision web1")
	if err != nil {
		t.Fatal(err)
	}
	if r.NetworkID != "lan" || r.Pool != "servers" || r.Address != addr("192.168.10.12") || r.Prefix != netip.MustParsePrefix("192.168.10.0/24") ||
		r.Gateway != addr("192.168.10.1") || r.VLAN != 10 || r.By != "admin" || r.At.Unix() != 1_800_000_000 {
		t.Fatalf("reservation = %+v", r)
	}
	if v := statusOf(t, s, "lan")["192.168.10.12"]; v.Status != Reserved || v.Why != "provision web1" {
		t.Fatalf("status = %+v", v)
	}
}

func TestReserveRefusesAddressThatIsNotFree(t *testing.T) {
	ctx := context.Background()
	hosts := func(context.Context) (map[netip.Addr][]string, error) {
		return map[netip.Addr][]string{addr("192.168.10.13"): {"web1"}}, nil
	}
	s := newStore(t, hosts)
	lan(t, s)
	if err := s.SetEntry(ctx, "admin", addr("192.168.10.14"), EntryReserved, "taken"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEntry(ctx, "admin", addr("192.168.10.15"), EntryExcluded, "printer"); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"192.168.10.1", "192.168.10.13", "192.168.10.14", "192.168.10.15", "192.168.10.0", "192.168.10.255"} {
		if _, err := s.Reserve(ctx, "admin", "lan", "", addr(a), "x"); !errors.Is(err, ErrAddressTaken) {
			t.Fatalf("%s: %v", a, err)
		}
	}
	// The existing reservation is untouched (no upsert).
	if v := statusOf(t, s, "lan")["192.168.10.14"]; v.Entry == nil || v.Entry.Note != "taken" {
		t.Fatalf("existing reservation overwritten: %+v", v)
	}
}

func TestReserveRejectsAddressOutsideNetworkOrPool(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, nil)
	lan(t, s)
	cases := []struct {
		name, network, pool, addr, user, note string
		want                                  error
	}{
		{"outside network", "lan", "", "192.168.11.5", "admin", "", nil},
		{"outside pool", "lan", "servers", "192.168.10.30", "admin", "", nil},
		{"ipv6", "lan", "", "fd00::5", "admin", "", nil},
		{"unknown network", "nope", "", "192.168.10.30", "admin", "", ErrNotFound},
		{"unknown pool", "lan", "nope", "192.168.10.12", "admin", "", ErrNotFound},
		{"bad user", "lan", "", "192.168.10.30", "a b", "", nil},
		{"bad note", "lan", "", "192.168.10.30", "admin", "a\x00b", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.Reserve(ctx, c.user, c.network, c.pool, addr(c.addr), c.note)
			if err == nil {
				t.Fatal("reserved")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
	if _, err := s.Reserve(ctx, "admin", "lan", "", netip.Addr{}, ""); err == nil {
		t.Fatal("invalid address reserved")
	}
}

func TestReserveIsAtomicUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, nil)
	lan(t, s)
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Reserve(ctx, "admin", "lan", "servers", addr("192.168.10.16"), "race")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrAddressTaken):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent reservations of one address succeeded", ok)
	}
}
