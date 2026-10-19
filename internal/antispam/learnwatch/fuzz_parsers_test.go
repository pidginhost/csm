package learnwatch

import (
	"strings"
	"testing"
)

func FuzzBaseName(f *testing.F) {
	for _, s := range []string{"1.M1.host:2,S", "a:2,", "..", "", "a/b:2,"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		base, ok := BaseName(name)
		if !ok {
			return
		}
		if base == "" || base == "." || base == ".." || strings.ContainsAny(base, "/\x00") || !strings.HasPrefix(name, base) {
			t.Fatalf("BaseName(%q) = %q", name, base)
		}
	})
}
