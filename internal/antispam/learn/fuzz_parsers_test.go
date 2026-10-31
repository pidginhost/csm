package learn

import (
	"bytes"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

func FuzzParseInspection(f *testing.F) {
	a, b := digest('a'), digest('b')
	f.Add(reply(f, hit(a, a, 1, 2)), "")
	f.Add(reply(f, hit(a, b, 0.8, 2), miss(b)), "")
	f.Add(reply(f, miss(a)), string(a))
	f.Add([]byte("garbage"), "")
	f.Add([]byte{}, "")
	f.Add([]byte(`{"results":{},"errors":{},"complete":true,"distinct":null}`), "")
	f.Add([]byte(`{"results":{ },"errors":{ },"complete":true,"distinct":0}`), "")
	f.Add([]byte(`{"results":{},"errors":["too many digests"],"complete":false,"distinct":65}`), "")
	f.Add([]byte(`{"results":{},"errors":["cannot process message"],"complete":false,"distinct":0}`), "")
	f.Add([]byte(strings.Replace(string(reply(f, miss(a))), `"value":0`, `"value":503,"value":0`, 1)), "")
	f.Add([]byte(strings.Replace(string(reply(f, miss(a))), `"value":0`, `"value":1e-400`, 1)), "")
	f.Fuzz(func(t *testing.T, body []byte, explicit string) {
		var ds []Digest
		if explicit != "" {
			ds = []Digest{Digest(explicit)}
		}
		insp, err := ParseInspection(body, ds)
		if err != nil {
			if insp.Distinct != 0 || len(insp.Results) != 0 {
				t.Fatal("failed inspection returned partial results")
			}
			return
		}
		if insp.Distinct < 0 || insp.Distinct > MaxExplicitDigests || insp.Distinct != len(insp.Results) {
			t.Fatal("distinct count differs from results")
		}
		if ds != nil && (insp.Distinct != 1 || insp.Results[0].Queried != ds[0]) {
			t.Fatal("explicit inspection answered another digest set")
		}
		seen := map[Digest]bool{}
		for _, r := range insp.Results {
			if seen[r.Queried] {
				t.Fatal("duplicate result accepted")
			}
			seen[r.Queried] = true
			if _, err := ParseDigest(string(r.Queried)); err != nil {
				t.Fatal("invalid queried digest accepted")
			}
			if r.Found {
				if _, err := ParseDigest(string(r.Stored)); err != nil || !r.Confirmed || r.Flag != 1 ||
					math.IsNaN(r.Prob) || r.Prob < 0 || r.Prob > 1 || r.Value < 0 {
					t.Fatalf("invalid hit accepted: %+v", r)
				}
				if ds != nil && r.Stored != r.Queried {
					t.Fatal("explicit near match accepted")
				}
			} else if r.Value != 0 || r.Prob != 0 || r.Stored != "" || r.Flag != 0 || r.Confirmed {
				t.Fatalf("invalid miss accepted: %+v", r)
			}
		}
	})
}

func FuzzTextPartMessages(f *testing.F) {
	f.Add([]byte(altMessage), uint8(2))
	f.Add([]byte(nested(3)), uint8(1))
	f.Add([]byte("Content-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\n"), uint8(2))
	f.Fuzz(func(t *testing.T, msg []byte, budget uint8) {
		if len(msg) > MaxBody {
			return
		}
		limit := int(budget) % (MaxExplicitDigests + 1)
		count := 0
		for m := range textPartMessages(msg, limit) {
			count++
			if count > limit {
				t.Fatal("derived messages exceeded the inspection budget")
			}
			parsed, err := mail.ReadMessage(bytes.NewReader(m))
			if err != nil {
				t.Fatalf("derived message does not parse: %v", err)
			}
			if strings.HasPrefix(strings.ToLower(parsed.Header.Get("Content-Type")), "multipart/") {
				t.Fatal("derived message is multipart")
			}
			// Only the rebuilt MIME lines can grow; nothing is copied twice.
			if len(m) > len(msg)+64 {
				t.Fatal("derived message is larger than its source")
			}
		}
	})
}

func FuzzTextOnlyMessage(f *testing.F) {
	f.Add([]byte(pdfMessage))
	f.Add([]byte(altMessage))
	f.Add([]byte(nested(3)))
	f.Add([]byte("Content-Type: multipart/digest; boundary=d\n\n--d\n\n" + pdfMessage + "\n--d--\n"))
	f.Add([]byte("Content-Type: text/plain\nContent-Disposition: attachment; filename\n\nattached text"))
	f.Fuzz(func(t *testing.T, msg []byte) {
		got := textOnlyMessage(msg)
		if got == nil {
			return
		}
		if again := textOnlyMessage(got); !bytes.Equal(again, got) {
			t.Fatal("text-only body changes when inspected again")
		}
		if bytes.Equal(got, msg) {
			return
		}
		m, err := mail.ReadMessage(bytes.NewReader(got))
		if err != nil {
			t.Fatalf("rebuilt message does not parse: %v", err)
		}
		// A missing content type is text/plain (RFC 2045).
		mt, params := "text/plain", map[string]string(nil)
		if ct := m.Header.Get("Content-Type"); ct != "" {
			if mt, params, err = mime.ParseMediaType(ct); err != nil {
				t.Fatalf("rebuilt content type: %v", err)
			}
		}
		if strings.HasPrefix(mt, "multipart/") {
			r := multipart.NewReader(m.Body, params["boundary"])
			for {
				p, err := r.NextRawPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("rebuilt multipart: %v", err)
				}
				pt := "text/plain"
				if ct := p.Header.Get("Content-Type"); ct != "" {
					if pt, _, err = mime.ParseMediaType(ct); err != nil {
						t.Fatalf("rebuilt part type: %v", err)
					}
				}
				if pt != "text/plain" && pt != "text/html" {
					t.Fatalf("rebuilt leaf %q", pt)
				}
			}
		} else if mt != "text/plain" && mt != "text/html" {
			t.Fatalf("rebuilt type %q", mt)
		}
		// Rebuilt MIME lines and a longer boundary per kept part are the only
		// growth; no content is copied twice.
		if len(got) > len(msg)+256+64*MaxExplicitDigests {
			t.Fatal("rebuilt message is larger than its source")
		}
	})
}
