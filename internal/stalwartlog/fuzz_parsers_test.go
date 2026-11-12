package stalwartlog

import (
	"regexp"
	"testing"
)

var eventNameRe = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)

func FuzzParse(f *testing.F) {
	for _, line := range []string{lineAuthSuccess, lineScanBan, lineQueued} {
		f.Add(line)
		f.Add(line + "\n")
		f.Add(line + "\r\n")
	}
	f.Fuzz(func(t *testing.T, line string) {
		ev, ok := Parse(line)
		if !ok {
			return
		}
		if !eventNameRe.MatchString(ev.Name) {
			t.Fatalf("event name %q does not match the grammar", ev.Name)
		}
		_, _ = ev.Session()
	})
}
