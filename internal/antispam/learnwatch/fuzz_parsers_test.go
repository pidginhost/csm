package learnwatch

import (
	"math"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

func FuzzBaseName(f *testing.F) {
	for _, s := range []string{"1.M1.host:2,S", "a:2,", "..", "", "a/b:2,", "a:2,S/b", "a:2,S\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		base, ok := BaseName(name)
		if !ok {
			return
		}
		if base == "" || base == "." || base == ".." || strings.ContainsAny(name, "/\x00") || !strings.HasPrefix(name, base) {
			t.Fatalf("BaseName(%q) = %q", name, base)
		}
	})
}

func FuzzParsePasswd(f *testing.F) {
	f.Add([]byte(passwd), "tenant1")
	f.Add([]byte("a:b:c"), "a")
	f.Add([]byte("tenant1:x:4294967296:1001::/home/tenant1:/bin/bash\n"), "tenant1")
	f.Add([]byte("tenant1:x:1001:4294967295::/home/tenant1:/bin/bash\n"), "tenant1")
	f.Add([]byte("tenant1:x:1001:1001::/home/tenant1\x00other:/bin/bash\n"), "tenant1")
	f.Fuzz(func(t *testing.T, data []byte, name string) {
		got, _, err := Accounts(fakeSource{users: []string{name}, passwd: string(data)})
		if err != nil {
			return
		}
		for _, a := range got {
			if a.Name != name || a.Name == "root" || !admission.ValidAccountName(a.Name) ||
				a.UID <= 0 || int64(a.UID) >= math.MaxUint32 || a.GID < 0 || int64(a.GID) >= math.MaxUint32 ||
				!filepath.IsAbs(a.Home) || a.Home == "/" || filepath.Clean(a.Home) != a.Home || strings.ContainsRune(a.Home, 0) {
				t.Fatalf("bad account %+v", a)
			}
		}
	})
}

func FuzzParseMailboxPasswd(f *testing.F) {
	f.Add([]byte("user:x:1:1::/x:/x\n../../x:x\n"), 3)
	f.Add([]byte("a\x00b:x\n\xff:x\n"), 1)
	f.Add([]byte("a:x\na:x\nb:x\n"), 2)
	f.Add([]byte("../x:x\n../x:x\n../x:x\n"), 1)
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		if limit < 0 || limit > 1000 {
			return
		}
		names, skips := ParseMailboxPasswd(data, limit)
		if len(names) > limit {
			t.Fatalf("%d names over limit %d", len(names), limit)
		}
		if len(names)+len(skips) > limit+1 {
			t.Fatalf("%d names and %d skips over record limit %d", len(names), len(skips), limit)
		}
		if !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
			t.Fatalf("names are not sorted and distinct: %v", names)
		}
		for _, n := range names {
			if !ValidMailbox(n) {
				t.Fatalf("invalid name %q returned", n)
			}
		}
	})
}

func FuzzParseVerdict(f *testing.F) {
	for _, s := range []string{
		"Subject: x\r\n\r\nbody", " x\r\n", "X-Spam-Status: No\r\n\r\n", "a:b\nc",
		"Subject: x\rX-Spam-Status: Yes\r\n\r\n",
		"X-Spam-Status: No,\x00\r\n\r\n", "X-Spam-Status: No\r",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseVerdict(data)
		tagged := append([]byte("X-Spam-Status: Yes\r\n"), data...)
		if ParseVerdict(tagged) == VerdictEligible {
			t.Fatalf("Yes verdict line read as eligible: %q", tagged)
		}
		for _, bad := range []byte{'\r', '\x00'} {
			malformed := append([]byte("X-Spam-Status: No, "), bad, 'x')
			malformed = append(malformed, data...)
			if got := ParseVerdict(malformed); got != VerdictMalformed {
				t.Fatalf("invalid header read as %v: %q", got, malformed)
			}
		}
	})
}
