package checks

import (
	"runtime"
	"strings"
	"testing"
)

func TestParsePatternRecordXFFRetainedMemory(t *testing.T) {
	// Consumers retaining only the bounded XFF must not also retain its
	// discarded client prefix. Other record fields and the raw line expire.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	xff := func() string {
		line := `198.51.100.9 - - ` + prTime + ` "GET /a HTTP/1.1" 200 1 "-" "UA" "` +
			strings.Repeat("garbage, ", 1<<17) + `203.0.113.7"`
		r, ok := parsePatternRecord(line)
		if !ok || r.Target != "/a" || len(r.XFF) > patternMaxExtension {
			t.Fatalf("oversized extension changed the record: ok=%v record=%+v", ok, r)
		}
		return r.XFF
	}()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(xff)
	// Allow ample runtime bookkeeping without allowing the megabyte prefix
	// to remain reachable through a small suffix.
	if after.HeapAlloc > before.HeapAlloc && after.HeapAlloc-before.HeapAlloc > 64<<10 {
		t.Fatalf("bounded XFF retained %d heap bytes", after.HeapAlloc-before.HeapAlloc)
	}
}
