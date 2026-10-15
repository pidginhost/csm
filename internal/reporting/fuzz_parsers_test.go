package reporting

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

func FuzzRetryAfter(f *testing.F) {
	for _, value := range []string{"", "1", "86400", "-1", "99999999999999999999", "99999999999999999999garbage", "Wed, 21 Oct 2026 07:28:00 GMT"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		got := retryAfter(http.Header{"Retry-After": {value}}, time.Unix(0, 0))
		if got < 0 {
			t.Fatalf("negative retry delay for %q: %v", value, got)
		}
		if seconds, err := strconv.ParseUint(value, 10, 32); err == nil && got != time.Duration(seconds)*time.Second {
			t.Fatalf("seconds changed for %q: %v", value, got)
		}
	})
}
