package learn

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/mail"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Many small parts must not multiply a large shared header into memory
// before the engine applies its inspection budget.
func TestEngineMultipartSeedBoundsAllocation(t *testing.T) {
	msg := []byte("Subject: " + strings.Repeat("s", 256<<10) + "\n" +
		"Content-Type: multipart/mixed; boundary=b\n\n" +
		strings.Repeat("--b\nContent-Type: text/plain\n\nbody\n", 128) + "--b--\n")
	for _, accept := range []bool{false, true} {
		t.Run(fmt.Sprint("accept=", accept), func(t *testing.T) {
			f := newAuditFixture(t)
			insp := Inspection{Distinct: 2}
			if accept {
				insp.Distinct = MaxExplicitDigests
			}
			for i := range insp.Distinct {
				insp.Results = append(insp.Results, Result{Queried: Digest(fmt.Sprintf("%064x", i))})
			}
			calls := 0
			e := &Engine{cfg: EngineConfig{Ledger: f.ledger, Client: inspectionHook{inspect: func(context.Context, []byte) (Inspection, error) {
				calls++
				if accept {
					return Inspection{Distinct: 1, Results: insp.Results[:1]}, nil
				}
				return Inspection{}, nil
			}}}}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			a, part, err := e.seedFromPart(context.Background(), Source{}, msg, insp, nil)
			runtime.ReadMemStats(&after)
			wantCalls := insp.Distinct
			if accept {
				wantCalls = 1
			}
			if err != nil || (part != nil) != accept || (a.Seed != nil) != accept || calls != wantCalls {
				t.Fatalf("seed=%v part=%v calls=%d err=%v", a.Seed, part != nil, calls, err)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > uint64(16*len(msg)) {
				t.Fatalf("allocated %d bytes for a %d-byte message and %d inspections", allocated, len(msg), calls)
			}
		})
	}
}

func TestTextPartMessagesSkipsAttachedMultipart(t *testing.T) {
	msg := "Subject: s\nContent-Type: multipart/mixed; boundary=outer\n\n" +
		"--outer\nContent-Type: multipart/alternative; boundary=inner\n" +
		"Content-Disposition: attachment\n\n" +
		"--inner\nContent-Type: text/plain\n\nattached text longer than the body\n--inner--\n" +
		"--outer\nContent-Type: text/plain\n\ninline body\n--outer--\n"
	got := slices.Collect(textPartMessages([]byte(msg), MaxExplicitDigests))
	if len(got) != 1 || !strings.HasSuffix(string(got[0]), "\n\ninline body") {
		t.Fatalf("expected only the inline body, got %q", got)
	}
}

func TestTextPartMessagesBudgetKeepsLargestInWireOrder(t *testing.T) {
	msg := "Content-Type: multipart/mixed; boundary=outer\n\n" +
		strings.Repeat("--outer\nContent-Type: text/plain\n\na\n", 100) +
		"--outer\nContent-Type: text/plain\n\nfirst equal\n" +
		"--outer\nContent-Type: multipart/alternative; boundary=inner\n\n" +
		"--inner\nContent-Type: text/plain\n\nother equal\n--inner--\n" +
		"--outer\nContent-Type: text/plain\n\nlast is the largest\n--outer--\n"
	for _, limit := range []int{0, 1, 2, 3} {
		got := slices.Collect(textPartMessages([]byte(msg), limit))
		want := []string{"last is the largest", "first equal", "other equal"}
		if len(got) != limit {
			t.Fatalf("budget %d yielded %d messages", limit, len(got))
		}
		for i, raw := range got {
			m, err := mail.ReadMessage(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(m.Body)
			if err != nil || string(body) != want[i] {
				t.Fatalf("budget %d part %d: body=%q err=%v", limit, i, body, err)
			}
		}
	}
}

func TestTextPartMessagesPreservesBase64(t *testing.T) {
	msg := []byte("Subject: folded\r\n subject\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/html; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\nPHA+c3BhbTwvcD4=\r\n--b--\r\n")
	got := slices.Collect(textPartMessages(msg, 1))
	if len(got) != 1 {
		t.Fatalf("got %d messages", len(got))
	}
	want := "Subject: folded\r\n subject\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nPHA+c3BhbTwvcD4="
	if string(got[0]) != want {
		t.Fatalf("derived message %q", got[0])
	}
}
