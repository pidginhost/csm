package checks

import "testing"

// A request-controlled first field must never become direct, whatever
// valid or malformed format bytes follow it.
func FuzzApacheLogFormat(f *testing.F) {
	for _, seed := range []string{"", "%h %l %u %t", "%{X}i\\n%v %a", "%!200,304<{c}a", "%", "%{", "%^t", "\\", "[client\\ %a] %M% ,\\ %{Referer}i", "%-+7{x}e", " %v %{X}i", "%{SERVER_NAME}t", "%{}t", `\[%{X}i]`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, format string) {
		apacheFormatLogsClientValue(format, false)
		apacheFormatLogsClientValue(format, true)
		liteSpeedFormatLogsClientValue(format, false)
		liteSpeedFormatLogsClientValue(format, true)
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
			if value, ok := liteSpeedFormatLogsClientValue(prefix+format, split); ok && !value {
				t.Fatalf("LiteSpeed request client classified direct: %q, split=%v", format, split)
			}
			if value, ok := apacheFormatLogsClientValue(" \t "+prefix+format, split); ok && !value {
				t.Fatalf("leading whitespace hides request client: %q, split=%v", format, split)
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

// Request values cannot become trusted through a prefix, string boundary
// or disabled escaping, whatever format suffix the fuzzer supplies.
func FuzzNginxLogFormat(f *testing.F) {
	for _, seed := range []string{"$remote_addr - $remote_user", "${http_x}", "$", "${", "{\"ip\":\"$remote_addr\"}", "$a\n$b c"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, format string) {
		nginxFormatLogsClientValue("http", "default", nil, format)
		nginxFormatLogsClientValue("stream", "default", nil, format)
		if value, ok := nginxFormatLogsClientValue("http", "default", nil, "  $http_x_client ", format); ok && !value {
			t.Fatalf("request client field classified direct: %q", format)
		}
		if value, ok := nginxFormatLogsClientValue("http", "default", nil, "[$http_x_client] ", format); ok && !value {
			t.Fatalf("bracketed request client classified direct: %q", format)
		}
		if value, ok := nginxFormatLogsClientValue("http", "none", nil, "$remote_addr $request_body ", format); ok && !value {
			t.Fatalf("unescaped request value classified direct: %q", format)
		}
		if value, ok := nginxFormatLogsClientValue("stream", "default", nil, "$request_time ", format); ok && !value {
			t.Fatalf("HTTP-only name in stream = direct, want request value: %q", format)
		}
		custom := map[string]bool{"realip_remote_addr": true}
		if value, ok := nginxFormatLogsClientValue("http", "default", custom, "$realip_remote_addr ", format); ok && !value {
			t.Fatalf("user-defined peer spelling classified direct: %q", format)
		}
		for _, module := range []string{"http", "stream"} {
			if value, ok := nginxFormatLogsClientValue(module, "default", nil, "$realip_remote_addr ", format); ok && !value {
				t.Fatalf("optional peer spelling classified direct without module proof: %q, module=%s", format, module)
			}
		}
	})
}
