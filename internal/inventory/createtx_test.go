// SPDX-License-Identifier: AGPL-3.0-or-later

package inventory

import (
	"context"
	"errors"
	"testing"
)

// CreateTx: host creation inside a caller's transaction (PV-06).

func TestCreateTxRollsBackWithTheCallersTransaction(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTx(ctx, tx, validHost(), CreateOptions{}); err != nil {
		t.Fatalf("CreateTx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "web-01"); !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("Get after rollback = %v, want ErrHostNotFound", err)
	}
}

func TestCreateTxCommitsAndRejectsDuplicatesAndInvalidHosts(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTx(ctx, tx, validHost(), CreateOptions{}); err != nil {
		t.Fatalf("CreateTx: %v", err)
	}
	if _, err := s.CreateTx(ctx, tx, validHost(), CreateOptions{}); !errors.Is(err, ErrHostExists) {
		t.Fatalf("duplicate CreateTx = %v, want ErrHostExists", err)
	}
	bad := validHost()
	bad.ID = "Bad ID"
	var ve *ValidationError
	if _, err := s.CreateTx(ctx, tx, bad, CreateOptions{}); !errors.As(err, &ve) {
		t.Fatalf("invalid CreateTx = %v, want ValidationError", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "web-01")
	if err != nil || len(got.Endpoints) != 2 || len(got.Groups) != 2 {
		t.Fatalf("Get = %+v, %v", got, err)
	}
}
