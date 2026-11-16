package stalwartapi

import "testing"

func FuzzStalwartSocketAddress(f *testing.F) {
	for _, seed := range []string{"0100007F:1F90", "00000000000000000000000001000000:01BB", "", "bad:port"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		addr, err := procSocketAddress(raw)
		if err == nil && !addr.IsValid() {
			t.Fatal("successful parse returned an invalid socket address")
		}
	})
}
