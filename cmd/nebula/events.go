// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Signed executor events (M10-1). The CLI verifies the chain itself with
// the key the executor reports; compare its fingerprint with the one you
// noted at install time (`nebula events key`).

const eventsPage = 1000

func eventsCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, w io.Writer) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "key":
		r, err := c.ListEvents(ctx, &pb.ListEventsRequest{Limit: 1, Newest: true})
		if err != nil {
			return err
		}
		pub := ed25519.PublicKey(r.GetPublicKey())
		fmt.Fprintf(w, "event key   %s\n", events.Fingerprint(pub))
		fmt.Fprintf(w, "public key  %s\n", base64.StdEncoding.EncodeToString(pub))
		fmt.Fprintf(w, "events      %d\n", r.GetHeadSeq())
		return nil
	case "verify":
		return eventsVerify(ctx, c, w)
	case "list":
		return eventsList(ctx, c, args, w)
	default:
		return fmt.Errorf("unknown events command %q (list, key, verify)", sub)
	}
}

func toRecords(es []*pb.Event) []events.Record {
	out := make([]events.Record, 0, len(es))
	for _, e := range es {
		out = append(out, events.Record{Seq: e.GetSeq(), Body: e.GetBody(), PrevHash: e.GetPrevHash(), Hash: e.GetHash(), Sig: e.GetSignature()})
	}
	return out
}

// eventsVerify walks the whole chain from event 1.
func eventsVerify(ctx context.Context, c pb.ExecutorServiceClient, w io.Writer) error {
	var after int64
	var prev []byte
	var pub ed25519.PublicKey
	for {
		r, err := c.ListEvents(ctx, &pb.ListEventsRequest{AfterSeq: after, Limit: eventsPage})
		if err != nil {
			return err
		}
		if pub == nil {
			pub = ed25519.PublicKey(r.GetPublicKey())
		} else if !pub.Equal(ed25519.PublicKey(r.GetPublicKey())) {
			return errors.New("the event key changed while reading")
		}
		recs := toRecords(r.GetEvents())
		if len(recs) == 0 {
			break
		}
		if after == 0 && recs[0].Seq != 1 {
			return fmt.Errorf("the chain does not start at event 1 (first is %d)", recs[0].Seq)
		}
		if err := events.Verify(pub, recs, prev); err != nil {
			return err
		}
		if recs[0].Seq != after+1 {
			return fmt.Errorf("event %d is missing", after+1)
		}
		after, prev = recs[len(recs)-1].Seq, recs[len(recs)-1].Hash
		if len(recs) < eventsPage {
			break
		}
	}
	fmt.Fprintf(w, "event key   %s\n", events.Fingerprint(pub))
	fmt.Fprintf(w, "verified    %d events, signatures and chain intact\n", after)
	if prev != nil {
		fmt.Fprintf(w, "head        %s\n", hex.EncodeToString(prev))
	}
	return nil
}

func eventsList(ctx context.Context, c pb.ExecutorServiceClient, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	after := fs.Int64("after", -1, "events after this sequence number (default: the newest ones)")
	limit := fs.Int("limit", 50, "at most this many (1 to 1000)")
	asJSON := fs.Bool("json", false, "one JSON object per line with hash and signature (for an offsite copy)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *limit < 1 || *limit > eventsPage {
		return errors.New("usage: nebula events [list] [--after N] [--limit 1-1000] [--json] | key | verify")
	}
	req := &pb.ListEventsRequest{Limit: int32(*limit)}
	if *after < 0 {
		req.Newest = true
	} else {
		req.AfterSeq = *after
	}
	r, err := c.ListEvents(ctx, req)
	if err != nil {
		return err
	}
	pub := ed25519.PublicKey(r.GetPublicKey())
	recs := toRecords(r.GetEvents())
	if err := events.Verify(pub, recs, nil); err != nil {
		return err
	}
	var bad error
	for _, rec := range recs {
		if *asJSON {
			line, err := json.Marshal(map[string]any{"seq": rec.Seq, "body": json.RawMessage(rec.Body), "prev_hash": hex.EncodeToString(rec.PrevHash),
				"hash": hex.EncodeToString(rec.Hash), "signature": base64.StdEncoding.EncodeToString(rec.Sig)})
			if err != nil {
				// Never a silent null in the offsite copy (review m101,
				// F4): keep the raw body and say what is wrong.
				line, _ = json.Marshal(map[string]any{"seq": rec.Seq, "body_base64": base64.StdEncoding.EncodeToString(rec.Body),
					"prev_hash": hex.EncodeToString(rec.PrevHash), "hash": hex.EncodeToString(rec.Hash),
					"signature": base64.StdEncoding.EncodeToString(rec.Sig), "error": "the body is not valid JSON"})
				if bad == nil {
					bad = fmt.Errorf("event %d: the body is not valid JSON", rec.Seq)
				}
			}
			fmt.Fprintln(w, string(line))
			continue
		}
		var b events.Body
		if err := json.Unmarshal(rec.Body, &b); err != nil {
			return fmt.Errorf("event %d: %w", rec.Seq, err)
		}
		keys := make([]string, 0, len(b.Attrs))
		for k := range b.Attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			if k == "level" {
				continue
			}
			parts = append(parts, k+"="+b.Attrs[k])
		}
		fmt.Fprintf(w, "%6d  %s  %-28s %s\n", rec.Seq, b.Time, displaySafe([]byte(b.Kind), 64), displaySafe([]byte(strings.Join(parts, " ")), 2000))
	}
	if !*asJSON {
		fmt.Fprintf(w, "(%d of %d events; signatures verified with %s)\n", len(recs), r.GetHeadSeq(), events.Fingerprint(pub))
	}
	return bad
}
