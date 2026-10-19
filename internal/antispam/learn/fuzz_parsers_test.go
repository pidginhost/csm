package learn

import (
	"math"
	"testing"
)

func FuzzParseInspection(f *testing.F) {
	a, b := digest('a'), digest('b')
	f.Add(reply(f, hit(a, a, 1, 2)), "")
	f.Add(reply(f, hit(a, b, 0.8, 2), miss(b)), "")
	f.Add(reply(f, miss(a)), string(a))
	f.Add([]byte("garbage"), "")
	f.Add([]byte{}, "")
	f.Fuzz(func(t *testing.T, body []byte, explicit string) {
		var ds []Digest
		if explicit != "" {
			ds = []Digest{Digest(explicit)}
		}
		insp, err := ParseInspection(body, ds)
		if err != nil {
			return
		}
		if insp.Distinct != len(insp.Results) {
			t.Fatal("distinct count differs from results")
		}
		for _, r := range insp.Results {
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
			} else if r.Value != 0 || r.Prob != 0 || r.Stored != "" {
				t.Fatalf("invalid miss accepted: %+v", r)
			}
		}
	})
}
