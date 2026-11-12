package checks

import "testing"

// A request-controlled first field must never become direct, whatever
// valid or malformed format bytes follow it.
func FuzzApacheLogFormat(f *testing.F) {
	for _, seed := range []string{"", "%h %l %u %t", "%{X}i\\n%v %a", "%!200,304<{c}a", "%", "%{", "%^t", "\\", "[client\\ %a] %M% ,\\ %{Referer}i", "%-+7{x}e"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, format string) {
		apacheFormatLogsClientValue(format, false)
		apacheFormatLogsClientValue(format, true)
		apacheErrorFormatLogsClientValue(format, true)
		apacheErrorFormatLogsClientValue(format, false)
		for _, split := range []bool{false, true} {
			prefix := "  %{X-Client}i "
			if split {
				prefix = "%v   %{X-Client}i "
			}
			if value, ok := apacheFormatLogsClientValue(prefix+format, split); ok && !value {
				t.Fatalf("request client field classified direct: %q, split=%v", format, split)
			}
		}
		if value, ok := apacheFormatLogsClientValue("[%{X-Client}i] "+format, false); ok && !value {
			t.Fatalf("bracketed request client classified direct: %q", format)
		}
		if value, ok := apacheErrorFormatLogsClientValue("[client %{X-Client}i] %M"+format, true); ok && !value {
			t.Fatalf("request error client classified direct: %q", format)
		}
		if value, ok := apacheErrorFormatLogsClientValue("%M\n[client %{X-Client}i] %M"+format, true); ok && !value {
			t.Fatalf("new error record = direct, want request value: %q", format)
		}
		if value, ok := apacheErrorFormatLogsClientValue("%M%{X-Missing}i% [client\\ %{X-Client}i] %M"+format, true); ok && !value {
			t.Fatalf("erasable message hides request client: %q", format)
		}
	})
}
