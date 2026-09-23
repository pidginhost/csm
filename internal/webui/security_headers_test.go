package webui

import "testing"

// The CSP had no base-uri, form-action, object-src or frame-ancestors, so
// an injected <base> or <form> could redirect relative URLs and posts. The
// legacy XSS auditor header is turned off: in the browsers that still honour
// it, "1; mode=block" can be abused to suppress page scripts.
func TestSecurityHeadersLockDownNavigationAndPlugins(t *testing.T) {
	directives := parseCSPDirectives(webUISecurityHeader(t, "Content-Security-Policy"))
	for name, want := range map[string]string{
		"base-uri":        "'none'",
		"form-action":     "'self'",
		"object-src":      "'none'",
		"frame-ancestors": "'none'",
	} {
		if got := directives[name]; len(got) != 1 || got[0] != want {
			t.Errorf("CSP %s = %v, want %s", name, got, want)
		}
	}
	if got := webUISecurityHeader(t, "X-XSS-Protection"); got != "0" {
		t.Errorf("X-XSS-Protection = %q, want 0", got)
	}
}
