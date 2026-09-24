package admission

import "testing"

func FuzzCanonicalTargets(f *testing.F) {
	for _, s := range []string{"192.0.2.1", "::ffff:192.0.2.1", "198.51.100.7/24", "2001:db8::/32", "fe80::1%eth0", "ip:192.0.2.1", "svc:192.0.2.1/tcp/22"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		for _, parse := range []func(string, Caps) (Target, error){CanonicalAddress, CanonicalPrefix, ParseTargetKey} {
			got, err := parse(raw, v6)
			if err != nil {
				if _, ok := ReasonOf(err); !ok {
					t.Fatalf("refusal without a reason: %v", err)
				}
				continue
			}
			again, err := ParseTargetKey(got.Key(), v6)
			if err != nil || again != got {
				t.Fatalf("key %q does not round-trip: %v", got.Key(), err)
			}
			for _, p := range protectedPrefixes {
				if p.Overlaps(got.Prefix()) {
					t.Fatalf("accepted %q overlaps protected %s", got.Key(), p)
				}
			}
		}
	})
}
