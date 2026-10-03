package checks

import "testing"

// Plain log fields are the common case on every scanned line; decoding one
// without escapes must not copy it.
func TestPatternDecodeFieldPlainFieldDoesNotAllocate(t *testing.T) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
	if allocs := testing.AllocsPerRun(100, func() {
		if got, over := patternDecodeField(ua, 512); got != ua || over {
			t.Fatalf("plain field decoded to %q (over %v)", got, over)
		}
	}); allocs != 0 {
		t.Fatalf("decoding a plain field allocated %.0f times", allocs)
	}
	if got, over := patternDecodeField(ua, 10); got != ua[:10] || !over {
		t.Fatalf("truncated plain field = %q (over %v), want %q true", got, over, ua[:10])
	}
	if got, over := patternDecodeField(`a\"b\\c\x41`, 64); got != `a"b\cA` || over {
		t.Fatalf("escaped field = %q (over %v)", got, over)
	}
}
