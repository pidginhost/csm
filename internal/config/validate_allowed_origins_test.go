package config

import "testing"

// webui.allowed_origins entries are compared to browser Origin headers, so
// anything that is not a bare https://host[:port] can never match and only
// hides a typo; validation says so up front.
func TestValidateWebUIAllowedOriginsShape(t *testing.T) {
	for _, bad := range []string{"ops.example.net", "http://ops.example.net:9443", "https://ops.example.net/ui", "https://user@ops.example.net"} {
		cfg := baseValidationConfig()
		cfg.WebUI.AllowedOrigins = []string{bad}
		if !hasResult(Validate(cfg), "error", "webui.allowed_origins") {
			t.Fatalf("entry %q accepted", bad)
		}
	}
	cfg := baseValidationConfig()
	cfg.WebUI.AllowedOrigins = []string{"https://ops.example.net:9443", "https://[2001:db8::1]:9443"}
	if hasResult(Validate(cfg), "error", "webui.allowed_origins") {
		t.Fatal("well-formed origins rejected")
	}
}
