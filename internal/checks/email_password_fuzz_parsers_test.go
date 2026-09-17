package checks

import (
	"errors"
	"testing"
)

func FuzzEmailPasswordHashParser(f *testing.F) {
	for _, seed := range []string{"{PLAIN}fixture", "{SHA.hex}00", "$6$rounds=999999999$salt$hash", "$2y$31$hash", "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$MTIzNDU2Nzg5MDEyMzQ1Ng"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		v, err := parseEmailPasswordHash(encoded)
		if err == nil {
			if v == nil || v.match == nil {
				t.Fatal("accepted hash has no verifier")
			}
		} else if v != nil || !errors.Is(err, errEmailHashInvalid) && !errors.Is(err, errEmailHashCost) && !errors.Is(err, errEmailHashUnsupported) {
			t.Fatalf("unexpected parser result: %v", err)
		}
	})
}
