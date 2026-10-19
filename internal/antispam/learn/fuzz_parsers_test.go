package learn

import (
	"math"
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
