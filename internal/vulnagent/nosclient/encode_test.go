// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBatchBodySendsHTMLCharactersUnescaped(t *testing.T) {
	// The packer counts finding records as the bytes of their encoding with
	// `<`, `>` and `&` left as they are. The body must carry them the same way,
	// or a batch packed to the budget grows past MaxBatchBytes when sent.
	f := json.RawMessage(`{"t":"<a>&"}`)
	body, err := encodeBatch(Batch{Seq: 1, Findings: []json.RawMessage{f}})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"batch_seq":1,"subjects":[],"findings":[{"t":"<a>&"}]}`
	if string(body) != want {
		t.Fatalf("body = %s, want %s", body, want)
	}
}

func TestBatchBodyOfHTMLRecordsIsNotEscapedOverTheLimit(t *testing.T) {
	// 63 findings of 16 KiB, all `<`, `>` and `&`, fill the budget a packer
	// counts for one batch (MaxBatchBytes less 16 KiB of envelope). Sent
	// unescaped they stay within MaxBatchBytes.
	const recordBytes = 16 << 10
	pad := strings.Repeat("<>&", recordBytes/3)
	f := json.RawMessage(`{"t":"` + pad[:recordBytes-len(`{"t":""}`)] + `"}`)
	fs := make([]json.RawMessage, 63)
	for i := range fs {
		fs[i] = f
	}
	body, err := encodeBatch(Batch{Seq: 1, Findings: fs})
	if err != nil {
		t.Fatalf("encodeBatch: %v", err)
	}
	if len(body) > MaxBatchBytes {
		t.Fatalf("body %d bytes, limit %d", len(body), MaxBatchBytes)
	}
	// The six bytes of the escape sequence for `<`, built from byte values.
	escaped := string([]byte{'\\', 'u', '0', '0', '3', 'c'})
	if strings.Contains(string(body), escaped) {
		t.Fatal("body escapes < as an unicode escape sequence")
	}
}
